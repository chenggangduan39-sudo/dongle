#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>
#include <unistd.h>
#include <pwd.h>

#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <mntent.h>
#include <blkid/blkid.h>
#include <sys/file.h>
#include <unistd.h>
#include <sys/stat.h>


// 调试日志系统
#define LOG(fmt, ...) printf("[SYSTEM] %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define ERROR(fmt, ...) fprintf(stderr, "[ERROR] %s:%d: " fmt " (原因: %s)\n", \
                              __FILE__, __LINE__, ##__VA_ARGS__, strerror(errno))

// 系统常量
#define MAX_DEVICES 100
#define HMAC_SECRET_SIZE 32
#define TOTAL_KEYS 100
#define KEY_SIZE 256
#define VALID_KEYS_FILE "valid_keys.dat"
#define USED_KEYS_FILE "used_keys.dat"
#define USB_VOLUME_NAME "qdreamer"
char LINUX_UID[32];
// 混淆密钥
static const unsigned char obfuscated_key[HMAC_SECRET_SIZE] = {
    0x8e,0xa2,0x6f,0xbc,0x45,0x2d,0xd3,0x1a,
    0x9c,0x7b,0x82,0xe9,0x10,0xfd,0x55,0x27,
    0x33,0x4a,0x91,0x88,0x0b,0xee,0xcf,0x63,
    0xf6,0x09,0x97,0x5d,0x74,0x30,0xac,0xde
};

// 许可证结构体
typedef struct {
    char **devices;
    int count;
    unsigned char hmac[SHA256_DIGEST_LENGTH];
} License;

/* ================= 密钥处理函数 ================= */
void get_hmac_key(unsigned char *key) {
    LOG("正在生成HMAC解密密钥...");
    for (int i = 0; i < HMAC_SECRET_SIZE; i++) {
        key[i] = obfuscated_key[i] ^ 0xAA;
    }
    LOG("密钥生成完成(长度:%d)", HMAC_SECRET_SIZE);
}

/* ================= 硬件指纹生成 ================= */
char* generate_hardware_id() {
    static char hwid[512] = {0};
    unsigned char key[HMAC_SECRET_SIZE];
    get_hmac_key(key);

    LOG("========= 硬件指纹生成开始 =========");
    
    LOG("Linux平台信息采集");
    FILE *fp = fopen("/sys/class/dmi/id/product_uuid", "r");
    if (fp) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), fp)) {
            strncat(hwid, buffer, sizeof(hwid)-1);
            LOG("DMI UUID已读取:%.24s...", buffer);
        } else {
            ERROR("DMI UUID读取失败");
        }
        fclose(fp);
    } else {
        ERROR("无法打开/sys/class/dmi/id/product_uuid");
    }

    // MAC地址
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock >= 0) {
        strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
        ifr.ifr_name[IFNAMSIZ-1] = '\0';
        
        if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
            unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
            char mac_str[18];
            snprintf(mac_str, sizeof(mac_str), "%02X%02X%02X%02X%02X%02X-", 
                    mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
            strncat(hwid, mac_str, sizeof(hwid)-1);
            LOG("MAC地址已获取:%s", mac_str);
        } else {
            ERROR("MAC地址获取失败");
        }
        close(sock);
    } else {
        ERROR("网络套接字创建失败");
    }

    // 磁盘序列号
    LOG("正在获取磁盘序列号...");
    fp = popen("hdparm -I /dev/sda 2>/dev/null | grep 'Serial Number'", "r");
    if (fp) {
        char buffer[256];
        while (fgets(buffer, sizeof(buffer), fp)) {
            if (strstr(buffer, "Serial Number")) {
                char *sn = strchr(buffer, ':') + 2;
                strncat(hwid, sn, sizeof(hwid)-1);
                LOG("磁盘序列号已获取:%.16s...", sn);
                break;
            }
        }
        pclose(fp);
    } else {
        ERROR("hdparm命令执行失败");
    }
    // HMAC签名生成
    LOG("正在计算HMAC签名(原始数据长度:%zu)...", strlen(hwid));
    unsigned char hmac[SHA256_DIGEST_LENGTH];
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, HMAC_SECRET_SIZE, EVP_sha256(), NULL);
    HMAC_Update(ctx, (unsigned char*)hwid, strlen(hwid));
    HMAC_Final(ctx, hmac, NULL);
    HMAC_CTX_free(ctx);

    static char final_id[65] = {0};
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        snprintf(&final_id[i*2], 3, "%02x", hmac[i]);
    }
    
    LOG("原始硬件信息:%.64s...", hwid);
    LOG("最终硬件指纹:%s", final_id);
    return final_id;
}

/* ================= U盘检测 ================= */
 const char* find_usb_drive() {
    static char mount_point[256] = {0};
    LOG("正在检测U盘...");
    // 获取当前用户ID与u盘固定地址
    /*uid_t uid = getuid();
    struct passwd *pw = getpwuid(uid);
    const char *fixed_path = NULL;
    if (pw != NULL) {
        char path_buff[256];
        snprintf(path_buff, sizeof(path_buff), "/media/%s/qdreamer", pw->pw_name);
        LOG("当前地址:%s", path_buff);
        fixed_path = path_buff;
    } else {
        ERROR("获取用户信息失败");
    }*/
    char path_buff[256];
    snprintf(path_buff, sizeof(path_buff), "/media/%s/qdreamer", LINUX_UID);
    // 检查固定挂载点
    const char *fixed_path = path_buff;
    //const char *fixed_path = "/media/hjp/qdreamer";
    struct stat st;
    if (stat(fixed_path, &st) == 0) {
        if (S_ISDIR(st.st_mode)) {
            strncpy(mount_point, fixed_path, sizeof(mount_point)-1);
            LOG("使用预设挂载点:%s", mount_point);
            return mount_point;
        }
    }

    // blkid检测
    blkid_cache cache;
    if (blkid_get_cache(&cache, NULL) != 0) {
        ERROR("blkid初始化失败");
        return NULL;
    }

    blkid_dev_iterate iter = blkid_dev_iterate_begin(cache);
    blkid_dev dev;
    while (blkid_dev_next(iter, &dev) == 0) {
        const char *devname = blkid_dev_devname(dev);
        const char *label = blkid_get_tag_value(cache, "LABEL", devname);
        LOG("检测到存储设备:%s (标签:%s)", devname, label ? label : "无");
        
        if (label && strcmp(label, USB_VOLUME_NAME) == 0) {
            FILE *mtab = setmntent("/proc/mounts", "r");
            struct mntent *ent;
            
            while ((ent = getmntent(mtab)) != NULL) {
                LOG("检查挂载点:%s → %s", ent->mnt_fsname, ent->mnt_dir);
                if (strcmp(ent->mnt_fsname, devname) == 0) {
                    strncpy(mount_point, ent->mnt_dir, sizeof(mount_point)-1);
                    endmntent(mtab);
                    blkid_put_cache(cache);
                    LOG("找到U盘挂载点:%s", mount_point);
                    return mount_point;
                }
            }
            endmntent(mtab);
        }
    }
    
    blkid_put_cache(cache);
    LOG("U盘检测完成.未找到目标设备");
    return NULL;
}


/* ================= 密钥管理 ================= */
int safe_strcmp(const char *a, const char *b) {
    size_t len_a = strlen(a);
    size_t len_b = strlen(b);
    if (len_a != len_b) return 1;
    
    int result = 0;
    for (size_t i = 0; i < len_a; i++) {
        result |= a[i] ^ b[i];
    }
    return result;
}

int load_usb_keys(char keys[][KEY_SIZE], int *max_keys) {
    const char *usb_path = find_usb_drive();
    if (!usb_path) {
        ERROR("未找到U盘:%s", USB_VOLUME_NAME);
        return -1;
    }

    char key_path[512];
    snprintf(key_path, sizeof(key_path), "%s/%s", usb_path, VALID_KEYS_FILE);
    LOG("正在加载密钥文件:%s", key_path);

    FILE *fp = fopen(key_path, "r");
    if (!fp) {
        ERROR("打开密钥文件失败");
        return -1;
    }

    int count = 0;
    char buffer[KEY_SIZE];
    while (count < *max_keys && fgets(buffer, sizeof(buffer), fp)) {
        size_t len = strcspn(buffer, "\n");
        buffer[len] = '\0';
        LOG("读取密钥[%d]:%.16s...", count+1, buffer);

        if (len < 8 || len >= KEY_SIZE-1) {
            ERROR("无效密钥长度:%zu", len);
            fclose(fp);
            return -1;
        }

        for (int i = 0; i < count; i++) {
            if (safe_strcmp(keys[i], buffer) == 0) {
                ERROR("发现重复密钥:%.8s...", buffer);
                fclose(fp);
                return -1;
            }
        }

        strncpy(keys[count], buffer, KEY_SIZE-1);
        count++;
    }
    fclose(fp);

    if (count == 0) {
        ERROR("密钥文件为空");
        return -1;
    }

    *max_keys = count;
    LOG("成功加载 %d 个密钥", count);
    return count;
}

int is_key_used(const char *key) {
    LOG("检查密钥是否已使用:%.8s...", key);
    FILE *fp = fopen(USED_KEYS_FILE, "r");
    if (!fp) return 0;
    LOG("打开使用记录文件成功");
    char buffer[KEY_SIZE];
    int found = 0;
    while (fgets(buffer, sizeof(buffer), fp)) {
        buffer[strcspn(buffer, "\n")] = '\0';
        if (safe_strcmp(buffer, key) == 0) {
            LOG("发现已使用密钥:%s", key);
            found = 1;
            break;
        }
    }
    fclose(fp);
    return found;
}

int record_used_key(const char *key) {
    LOG("正在记录已用密钥:%.8s...", key);
    FILE *fp = fopen(USED_KEYS_FILE, "a");
    if (!fp) {
        ERROR("无法打开使用记录文件");
        return -1;
    }


    if (flock(fileno(fp), LOCK_EX) != 0) {
        ERROR("文件加锁失败");
        fclose(fp);
        return -1;
    }


    fprintf(fp, "%s\n", key);
    fflush(fp);
    LOG("密钥已写入文件");


    flock(fileno(fp), LOCK_UN);


    fclose(fp);
    return 0;
}

/* ================= 许可证管理 ================= */
int validate_license(const char *path, License *license) {
    LOG("========= 许可证验证开始 =========");
    LOG("目标文件:%s", path);

    FILE *fp = fopen(path, "rb");
    if (!fp) {
        LOG("文件不存在，将创建新许可证");
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    long size = ftell(fp);
    rewind(fp);
    LOG("文件大小:%ld 字节", size);

    if (size < SHA256_DIGEST_LENGTH) {
        ERROR("文件过小(实际:%ld < 需求:%d)", size, SHA256_DIGEST_LENGTH);
        fclose(fp);
        return 0;
    }

    char *data = malloc(size);
    if (!data) {
        ERROR("内存分配失败(%ld字节)", size);
        fclose(fp);
        return 0;
    }
    LOG("已分配内存:%p", data);

    size_t read_size = fread(data, 1, size, fp);
    fclose(fp);
    if (read_size != (size_t)size) {
        ERROR("文件读取不完整(%zu/%ld)", read_size, size);
        free(data);
        return 0;
    }

    // HMAC验证
    LOG("开始HMAC验证...");
    unsigned char stored_hmac[SHA256_DIGEST_LENGTH];
    memcpy(stored_hmac, data + size - SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH);
    
    unsigned char computed_hmac[SHA256_DIGEST_LENGTH];
    unsigned char key[HMAC_SECRET_SIZE];
    get_hmac_key(key);
    
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, HMAC_SECRET_SIZE, EVP_sha256(), NULL);
    HMAC_Update(ctx, (unsigned char*)data, size - SHA256_DIGEST_LENGTH);
    HMAC_Final(ctx, computed_hmac, NULL);
    HMAC_CTX_free(ctx);

    if (memcmp(stored_hmac, computed_hmac, SHA256_DIGEST_LENGTH) != 0) {
        ERROR("HMAC校验失败");
        free(data);
        return 0;
    }
    LOG("HMAC校验通过");

    // 解析设备列表
    LOG("解析设备列表(数据区:%ld字节)", size - SHA256_DIGEST_LENGTH);
    char *ptr = data;
    license->count = 0;
    license->devices = malloc(MAX_DEVICES * sizeof(char*));
    if (!license->devices) {
        ERROR("设备列表内存分配失败");
        free(data);
        return 0;
    }

    while (ptr < data + size - SHA256_DIGEST_LENGTH && license->count < MAX_DEVICES) {
        size_t len = strlen(ptr);
        if (len == 0) {
            LOG("遇到空终止符，结束解析");
            break;
        }

        license->devices[license->count] = strdup(ptr);
        if (!license->devices[license->count]) {
            ERROR("设备字符串内存分配失败");
            break;
        }
        LOG("加载设备[%d]:%s", license->count+1, ptr);
        license->count++;
        ptr += len + 1;
    }

    free(data);
    LOG("共加载 %d 台设备", license->count);
    return 1;
}

int secure_save_license(const char *path, License *license) {
    LOG("========= 许可证保存开始 =========");
    LOG("目标路径:%s", path);

    // 计算总长度
    size_t total_len = 0;
    for (int i = 0; i < license->count; i++) {
        if (!license->devices[i]) continue;
        total_len += strlen(license->devices[i]) + 1;
    }
    LOG("数据总长度:%zu 字节", total_len);

    char *buffer = malloc(total_len + SHA256_DIGEST_LENGTH);
    if (!buffer) {
        ERROR("缓冲区分配失败");
        return 0;
    }
    LOG("分配缓冲区:%p 大小:%zu", buffer, total_len + SHA256_DIGEST_LENGTH);

    // 填充设备数据
    char *ptr = buffer;
    for (int i = 0; i < license->count; i++) {
        if (!license->devices[i]) continue;
        size_t len = strlen(license->devices[i]);
        memcpy(ptr, license->devices[i], len);
        ptr += len;
        *ptr++ = '\0';
        LOG("写入设备[%d]:%s", i+1, license->devices[i]);
    }

    // 计算HMAC
    unsigned char key[HMAC_SECRET_SIZE];
    get_hmac_key(key);
    
    HMAC_CTX *ctx = HMAC_CTX_new();
    HMAC_Init_ex(ctx, key, HMAC_SECRET_SIZE, EVP_sha256(), NULL);
    HMAC_Update(ctx, (unsigned char*)buffer, total_len);
    HMAC_Final(ctx, (unsigned char*)(buffer + total_len), NULL);
    HMAC_CTX_free(ctx);
    LOG("HMAC计算完成");

    // 写入文件
    FILE *fp = fopen(path, "wb");
    if (!fp) {
        ERROR("文件创建失败");
        free(buffer);
        return 0;
    }

    size_t write_size = fwrite(buffer, 1, total_len + SHA256_DIGEST_LENGTH, fp);
    fclose(fp);
    
    if (write_size != total_len + SHA256_DIGEST_LENGTH) {
        ERROR("文件写入不完整(%zu/%zu)", write_size, total_len + SHA256_DIGEST_LENGTH);
        free(buffer);
        return 0;
    }

    free(buffer);
    LOG("许可证保存成功");
    return 1;
}

/* ================= 主系统初始化 ================= */
int initialize() {
    LOG("\n====== 系统初始化开始 ======");
    const char *license_path = "license.dat";
    License license = {0};
    int ret = 0;

    // 生成硬件指纹
    LOG("正在生成硬件指纹...");
    const char *hwid = generate_hardware_id();
    LOG("当前硬件指纹:%s", hwid);

    // 验证许可证
    LOG("正在验证许可证文件:%s", license_path);
    if (!validate_license(license_path, &license)) {
        LOG("创建新的许可证文件");
        license.devices = malloc(MAX_DEVICES * sizeof(char*));
        if (!license.devices) {
            ERROR("设备列表初始化失败");
            return -1;
        }
        license.count = 0;
    }

    // 检查注册状态
    LOG("检查注册状态(已注册设备数:%d)", license.count);
    int registered = 0;
    for (int i = 0; i < license.count; i++) {
        if (license.devices[i] && strcmp(license.devices[i], hwid) == 0) {
            LOG("设备已注册(索引:%d)", i);
            registered = 1;
            break;
        }
    }

    if (!registered) {
        LOG("设备未注册，开始注册流程");
        if (license.count >= MAX_DEVICES) {
            ERROR("设备数量已达上限(最大:%d)", MAX_DEVICES);
            ret = -1;
        } else {
            LOG("执行密钥验证流程...");
            char valid_keys[TOTAL_KEYS][KEY_SIZE] = {0};
            int max_keys = TOTAL_KEYS;
            int key_count = load_usb_keys(valid_keys, &max_keys);
            if (key_count <= 0) {
                ERROR("密钥验证失败");
                ret = -1;
            } else {
                int valid_key_found = 0;
                char selected_key[KEY_SIZE] = {0};
                
                // 密钥对比
                for (int i = 0; i < key_count; i++) {
                    LOG("验证密钥[%d/%d]: %.12s...", i+1, key_count, valid_keys[i]);
                    if (!is_key_used(valid_keys[i])) {
                        LOG("发现有效未使用密钥");
                        strncpy(selected_key, valid_keys[i], KEY_SIZE);
                        valid_key_found = 1;
                        break;
                    }
                }

                if (!valid_key_found) {
                    ERROR("所有密钥已被使用");
                    ret = -1;
                } else if (record_used_key(selected_key) != 0) {
                    ERROR("密钥记录失败");
                    ret = -1;
                } else {
                    LOG("成功使用密钥: %.12s...", selected_key);
                    license.devices[license.count] = strdup(hwid);
                    if (!license.devices[license.count]) {
                        ERROR("设备信息存储失败");
                        ret = -1;
                    } else {
                        license.count++;
                        LOG("新设备注册成功(当前总数:%d)", license.count);
                        if (!secure_save_license(license_path, &license)) {
                            ERROR("许可证保存失败");
                            ret = -1;
                        }
                    }
                }
            }
        }
    } else {
        LOG("设备已注册，跳过注册流程");
    }

    // 清理资源
    LOG("清理资源...");
    if (license.devices) {
        for (int i = 0; i < license.count; i++) {
            if (license.devices[i]) {
                LOG("释放设备[%d]内存:%p", i, license.devices[i]);
                free(license.devices[i]);
            }
        }
        free(license.devices);
    }

    LOG("====== 系统初始化完成 ======\n");
    return ret;
}

int main(int argc, char **argv) {
    strcpy(LINUX_UID, argv[1]);
    printf("\n====== 程序启动 ======\n");
    int result = initialize();
    printf("初始化结果:%s\n", result == 0 ? "成功" : "失败");
    return result;
}