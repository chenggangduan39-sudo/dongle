#if defined(_WIN32) || defined(_WIN64)
#include <windows.h>
#else
#include <unistd.h>
#include <pwd.h>
#include <sys/utsname.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <mntent.h>
#include <blkid/blkid.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/file.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/hmac.h>
#include <openssl/sha.h>


// 调试日志系统
#define LOG(fmt, ...) printf("[SYSTEM] %s:%d: " fmt "\n", __FILE__, __LINE__, ##__VA_ARGS__)
#define ERROR(fmt, ...) fprintf(stderr, "[ERROR] %s:%d: " fmt " (原因: %s)\n", \
                              __FILE__, __LINE__, ##__VA_ARGS__, strerror(errno))

// 系统常量
#define MAX_DEVICES 100 //最大设备数
#define HMAC_SECRET_SIZE 32 //HMAC密钥长度
#define TOTAL_KEYS 100 //总密钥数
#define KEY_SIZE 256 //密钥长度
#define VALID_KEYS_FILE "valid_keys.dat" //有效密钥文件名
#define LICENSE_FILE "license.dat" //许可证文件名
#define USB_VOLUME_NAME "qdreamer" //U盘卷名
#define LOCAL_LICENSE_DIR  "/etc/usb_crypto" //本地许可证目录
#define LINUX_USB_UUID "1E09-081B" //Linux U盘UUID
#define WINDOWS_USB_UUID "91b2d608-8d4c-11f0-a03d-cc28aa34d757" //Windows U盘UUID
#define LOCAL_LICENSE_PATH LOCAL_LICENSE_DIR "/" LICENSE_FILE //本地许可证路径
char LINUX_UID[32]; //Linux UID
#define DEFAULT_DEVICE_LICENSE_DIR "/data/local/tmp/usb_crypto" //设备默认许可证目录

// 解析“主许可证路径”：优先按环境变量，其次按设备默认，最后退回 /etc/usb_crypto
static const char* resolve_primary_license_path(void) {
    static char path[512];

    // ① 明确指定完整文件路径（最优先）
    const char *p = getenv("TARGET_LICENSE_PATH"); // 例：/data/local/tmp/usb_crypto/license.dat
    if (p && *p) {
        snprintf(path, sizeof(path), "%s", p);
        return path;
    }

    // ② 只给目录，也行（我们补上 license.dat）
    const char *d = getenv("TARGET_LICENSE_DIR");  // 例：/data/local/tmp/usb_crypto
    if (d && *d) {
        snprintf(path, sizeof(path), "%s/%s", d, LICENSE_FILE);
        return path;
    }

    // ③ 如果声明“运行在设备上”，走设备默认目录
    const char *on_dev = getenv("RUN_ON_DEVICE");  // 设为 "1" 表示设备环境
    if (on_dev && strcmp(on_dev, "1") == 0) {
        snprintf(path, sizeof(path), "%s/%s", DEFAULT_DEVICE_LICENSE_DIR, LICENSE_FILE);
        return path;
    }

    // ④ 否则退回 PC 默认路径
    snprintf(path, sizeof(path), "%s", LOCAL_LICENSE_PATH); // /etc/usb_crypto/license.dat
    return path;
}

// 混淆密钥
static const unsigned char obfuscated_key[HMAC_SECRET_SIZE] = {
    0x8e,0xa2,0x6f,0xbc,0x45,0x2d,0xd3,0x1a,
    0x9c,0x7b,0x82,0xe9,0x10,0xfd,0x55,0x27,
    0x33,0x4a,0x91,0x88,0x0b,0xee,0xcf,0x63,
    0xf6,0x09,0x97,0x5d,0x74,0x30,0xac,0xde
};

// 结构体定义
typedef struct {
    char **devices;
    int count;
} License;

// 获取HMAC密钥
void get_hmac_key(unsigned char *key);
// 生成硬件指纹
char* generate_hardware_id();
// 查找U盘
const char* find_usb_drive();
// 验证U盘许可证
int validate_license(const char *usb_path, License *license);
// 验证许可证
static int validate_license_at(const char *license_path, License *license);
// 更新本地许可证缓存
static int update_local_license_cache(const char *usb_path);
// 安全保存许可证
static int secure_save_license(const char *usb_path, const License *license);
// 加载U盘密钥
int load_usb_keys(const char *usb_path, char keys[][KEY_SIZE], int *max_keys);
// 记录使用过的密钥
int record_used_key(const char *usb_path, const char *key);
// 安全比较两个字符串
int safe_strcmp(const char *a, const char *b);
// 常数时间比较两个字符串
int constant_time_memcmp(const unsigned char *a, const unsigned char *b, size_t len);
// 初始化
int initialize();

/*
功能：安全比较两个字符串
参数：
a：第一个字符串
b：第二个字符串
返回值：
0：相等
1：不相等
*/
int safe_strcmp(const char *a, const char *b) {
    if (!a || !b) return 1;
    return strcmp(a, b);
}
/*
功能：常数时间比较两个字符串
参数：
a：第一个字符串
b：第二个字符串
len：比较长度
返回值：
0：相等
1：不相等
*/
int constant_time_memcmp(const unsigned char *a, const unsigned char *b, size_t len) {
    unsigned char r = 0;
    for (size_t i = 0; i < len; i++) r |= a[i] ^ b[i];
    return r;
}

#if defined(_WIN32) || defined(_WIN64)
//机器标识获得
char* get_machine_guid() {
    
}

//mac地址获得
char* get_mac_address() {
    IP_ADAPTER_IDNO adapter_info[16];
    DWORD adapter_info_size = sizeof(adapter_info);
    DWORD status = GetAdaptersInfo(adapter_info, &adapter_info_size);
    if(status == ERROR_SUCCESS)
    {
        PIP_ADAPTER_INFO adapter = adapter_info;
        while(adapter)
        {
            if(adapter->Type == MIB_IF_TYPE_ENTHERNT && adapter->AddressLength == 6)
            {
                char mac_str[18];
                snprintf(mac_str,sizeof(mac_str),"%02X%02X%02X%02X%02X%02X",
                adapter->Address[0],adapter->Address[1],adapter->Address[2],
                adapter->Address[3],adapter->Address[4],adapter->Address[5]);
                return strdup(mac_str);
            }
            adapter = adapter->Next;
        }
    }
    return NULL;
}

//系统盘序列号获得
char* get_system_disk_serial_number() {
    char system_drive[4];
    GetWindowsDirectoryA(system_drive, sizeof(system_drive));
    system_drive[2] = '\0';

    char volume_name[MAX_PATH];
    DWORD volume_serial;
    DWORD max_component_length;
    DWORD file_system_flags;
    char file_system_name[MAX_PATH];

    if(GetVolumeInfomationA(system_drive,volume_name,sizeof(volume_name),
    &volume_serial,&max_component_length,&file_system_flags,
    file_system_name,sizeof(file_system_name)))
    {
        char serial_str[16];
        snprintf(serial_str,sizeof(serial_str),"%08X",volume_serial);
        return strdup(serial_str);
    }
    return NULL;
}
#endif

/* ================= HMAC 主密钥 ================= */
void get_hmac_key(unsigned char *key) {
    LOG("正在生成HMAC解密密钥...");
    for (int i = 0; i < HMAC_SECRET_SIZE; i++) {
        key[i] = obfuscated_key[i] ^ 0xAA;
    }
    LOG("密钥生成完成(长度:%d)", HMAC_SECRET_SIZE);
}

// 如果设置了环境变量 TARGET_HWID_HEX（64位十六进制），就用它；
// 否则回退到原来的 generate_hardware_id()
static const char* get_target_hwid() {
    static char hwid_hex[65] = {0};
    const char *env = getenv("TARGET_HWID_HEX");
    if (env && strlen(env) == 64) {
        // 简单校验是十六进制
        for (int i=0;i<64;i++){
            char c=env[i];
            if(!((c>='0'&&c<='9')||(c>='a'&&c<='f')||(c>='A'&&c<='F'))) 
            { 
                env=NULL; 
                break;
            }
        }
        if (env) { 
            strncpy(hwid_hex, env, 64); 
            hwid_hex[64]='\0'; 
            return hwid_hex; 
        }
    }
    // 兼容旧逻辑：没有外部 HWID 时，使用本机生成
    return generate_hardware_id();
}

/* ================= 硬件指纹生成 ================= */
char* generate_hardware_id() {
    #if defined(_WIN32) || defined(_WIN64)
    {
        //windows系统
        static char hwid[512] = {0};
        unsigned char key[HMAC_SECRET_SIZE];
        get_hmac_key(key);

        LOG("========= Windows硬件指纹生成开始 =========");
        
        LOG("Windows平台信息采集");
        char raw[2048] = {0};

        //机器标识
        char* machine_guid = get_machine_guid();
        if(machine_guid)
        {
            strncat(raw, machine_guid, sizeof(raw)-1);
            LOG("机器标识已获取:%s", machine_guid);
            free(machine_guid);
        }
        else
        {
            ERROR("机器标识获取失败");
        }

        //主网卡MAC地址
        char* mac_address = get_mac_address();
        if(mac_address)
        {
            strncat(raw, mac_address, sizeof(raw)-1);
            LOG("主网卡MAC地址已获取:%s", mac_address);
            free(mac_address);
        }
        else
        {
            ERROR("主网卡MAC地址获取失败");
        }

        //系统盘序列号
        char* system_disk_serial_number = get_system_disk_serial_number();
        if(system_disk_serial_number)
        {
            strncat(raw, system_disk_serial_number, sizeof(raw)-1);
            LOG("系统盘序列号已获取:%s", system_disk_serial_number);
            free(system_disk_serial_number);
        }
        else
        {
            ERROR("系统盘序列号获取失败");
        }

        //计算HWAC
        LOG("正在计算HMAC签名(原始数据长度:%zu)...", strlen(raw));
        unsigned char mac[SHA256_DIGEST_LENGTH];
        unsigned int maclen = 0;
        HMAC(EVP_sha256(), key, HMAC_SECRET_SIZE, (unsigned char*)raw, strlen(raw), mac, &maclen);

        //转换16进制
        char hex[65] = {0};
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            snprintf(hex + i*2, 3, "%02x", mac[i]);
        }
        snprintf(hwid, sizeof(hwid), "%s", hex);
        LOG("原始硬件信息:%.*s...", 60, raw);
        LOG("最终硬件指纹:%s", hwid);
        return hwid;
    }
    #elif defined(__linux__)
    {
        //linux系统
        static char hwid[512] = {0};
        unsigned char key[HMAC_SECRET_SIZE];
        get_hmac_key(key);

        LOG("========= Linux硬件指纹生成开始 =========");
        
        LOG("Linux平台信息采集");
        struct utsname uts;
        uname(&uts);
        char raw[1024] = {0};

        // DMI UUID
        FILE *fp = fopen("/sys/class/dmi/id/product_uuid", "r");
        if (fp) {
            char uuid[128] = {0};
            fgets(uuid, sizeof(uuid), fp);
            fclose(fp);
            strncat(raw, uuid, sizeof(raw)-1);
            LOG("DMI UUID已读取:%.*s...", 13, uuid);
        } else {
            ERROR("DMI UUID读取失败");
        }

        // MAC地址
        int sock = socket(AF_INET, SOCK_DGRAM, 0);
        if (sock >= 0) {
            struct ifreq ifr;
            memset(&ifr, 0, sizeof(ifr));
            strncpy(ifr.ifr_name, "eth0", IFNAMSIZ-1);
            if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                unsigned char *mac = (unsigned char *)ifr.ifr_hwaddr.sa_data;
                char mac_str[18];
                snprintf(mac_str, sizeof(mac_str), "%02X%02X%02X%02X%02X%02X-", 
                        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
                strncat(raw, mac_str, sizeof(raw)-1);
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
        FILE *fp2 = popen("lsblk -no SERIAL /dev/sda 2>/dev/null", "r");
        if (fp2) {
            char srl[128] = {0};
            fgets(srl, sizeof(srl), fp2);
            pclose(fp2);
            strncat(raw, srl, sizeof(raw)-1);
            LOG("磁盘序列号已获取:%s...", srl);
        } else {
            ERROR("磁盘序列号获取失败");
        }

        LOG("正在计算HMAC签名(原始数据长度:%zu)...", strlen(raw));
        unsigned char mac[SHA256_DIGEST_LENGTH];
        unsigned int maclen = 0;
        HMAC(EVP_sha256(), key, HMAC_SECRET_SIZE, (unsigned char*)raw, strlen(raw), mac, &maclen);

        char hex[65] = {0};
        for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            snprintf(hex + i*2, 3, "%02x", mac[i]);
        }
        snprintf(hwid, sizeof(hwid), "%s", hex);
        LOG("原始硬件信息:%.*s...", 60, raw);
        LOG("最终硬件指纹:%s", hwid);
        return hwid;
    }
    #endif
}

/* ================= U盘挂载点查找 ================= */
const char* find_usb_drive() {
    static char mount_point[256] = {0};
    LOG("正在检测U盘...");

    //判断U盘是否是我们提供的那个，使用USB的UUid来判断
    #if defined(_WIN32) || defined(_WIN64)
    {
        //windows系统
        LOG("windows系统");
        //获取U盘UUID
        DWORD dwSize = MAX_PATH;
        char szVolumeName[MAX_PATH] = {0};
        if(GetVolumeInformationA("E:\\", szVolumeName, sizeof(szVolumeName), NULL, NULL, NULL, NULL, 0))
        {
            LOG("U盘UUID:%s",szVolumeName);
        }
        if(strcmp(szVolumeName,WINDOWS_USB_UUID) == 0)
        {
            LOG("U盘UUID匹配");
        }
        else
        {
            LOG("U盘UUID不匹配");
            return NULL;
        }
    }
    #elif defined(__linux__)
    {
        //linux系统
        LOG("linux系统");
        blkid_cache cache = NULL;
        if(blkid_get_cache(&cache,NULL) != 0)
        {
            ERROR("blkid初始化失败");
            return NULL;
        }
        if(blkid_probe_all(cache) != 0)
        {
            ERROR("blkid探测失败");
            blkid_put_cache(cache);
            return NULL;
        }
        // 通过 by-uuid 动态解析真实设备名，避免硬编码 /dev/sdX1
        char linkpath[256] = {0};
        snprintf(linkpath, sizeof(linkpath), "/dev/disk/by-uuid/%s", LINUX_USB_UUID);
        char devpath[256] = {0};
        if (!realpath(linkpath, devpath))
        {
            ERROR("无法解析UUID符号链接: %s", linkpath);
            blkid_put_cache(cache);
            return NULL;
        }
        const char* uuid = blkid_get_tag_value(cache, "UUID", devpath);
        if(!uuid)
        {
            ERROR("U盘UUID获取失败: %s", devpath);
            blkid_put_cache(cache);
            return NULL;
        }
        LOG("设备: %s, U盘UUID:%s", devpath, uuid);
        if(strcmp(uuid, LINUX_USB_UUID) != 0)
        {
            LOG("U盘UUID不匹配");
            blkid_put_cache(cache);
            return NULL;
        }
        LOG("U盘UUID匹配");
        blkid_put_cache(cache);
    }
#endif

    char *username = getenv("SUDO_USER");
    if (username == NULL) {
        username = getenv("USER");
    }
    if (username == NULL) {
        struct passwd *pw = getpwuid(getuid());
        if (pw != NULL) {
            username = pw->pw_name;
        } else {
            username = (char *)"unknown";
        }
    }
    printf("Current username: %s\n", username);
    char path_buff[256];
    snprintf(path_buff, sizeof(path_buff), "/media/%s/%s", username, USB_VOLUME_NAME);

    // 检查固定挂载点
    const char *fixed_path = path_buff;
    struct stat st;
    //判断fix_path是否存在是否是目录
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
    blkid_probe_all(cache);
    blkid_dev_iterate iter = blkid_dev_iterate_begin(cache);
    blkid_dev dev;
    while (blkid_dev_next(iter, &dev) == 0) {
        const char *devname = blkid_dev_devname(dev);
        if (!devname) continue;
        const char *label = blkid_get_tag_value(cache, "LABEL", devname);
        if (label && strcmp(label, USB_VOLUME_NAME) == 0) {
            LOG("检测到存储设备:%s (标签:%s)", devname, label ? label : "无");
            // 查找挂载点
            FILE *mtab = setmntent("/proc/mounts", "r");
            if (mtab) {
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
    }
    blkid_dev_iterate_end(iter);
    blkid_put_cache(cache);
    LOG("U盘检测完成.未找到目标设备");
    return NULL;
}

/* ================= 密钥文件加载 ================= */
int load_usb_keys(const char *usb_path, char keys[][KEY_SIZE], int *max_keys) {
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
    // 遍历密钥文件
    while (count < *max_keys && fgets(buffer, sizeof(buffer), fp)) {
        size_t len = strcspn(buffer, "\n");
        buffer[len] = '\0';
        LOG("读取密钥[%d]:%.16s...", count+1, buffer);

        // 判断密钥长度是否合法
        if (len < 8 || len >= KEY_SIZE-1) {
            ERROR("无效密钥长度:%zu", len);
            fclose(fp);
            return -1;
        }

        // 判断密钥是否重复
        for (int i = 0; i < count; i++) {
            if (safe_strcmp(keys[i], buffer) == 0) {
                ERROR("发现重复密钥:%.8s...", buffer);
                fclose(fp);
                return -1;
            }
        }

        strncpy(keys[count], buffer, KEY_SIZE-1);
        count++;
        if (count >= TOTAL_KEYS) {
            LOG("警告：密钥数量已达系统上限(%d)", TOTAL_KEYS);
            break;
        }
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

/* =========== 消费密钥：从 valid_keys.dat 删除该行 =========== */
int record_used_key(const char *usb_path, const char *key) {
    // 现在的语义：注册成功后消费该密钥 —— 直接从 valid_keys.dat 删除
    if (!usb_path || !key || !key[0]) {
        ERROR("record_used_key: 参数无效");
        return -1;
    }

    char key_path[512], tmp_path[512];
    snprintf(key_path, sizeof(key_path), "%s/%s", usb_path, VALID_KEYS_FILE);
    snprintf(tmp_path,  sizeof(tmp_path),  "%s/%s", usb_path, "valid_keys.tmp");

    FILE *in = fopen(key_path, "r");
    if (!in) {
        ERROR("打开密钥文件失败: %s", key_path);
        return -1;
    }
    FILE *out = fopen(tmp_path, "w");
    if (!out) {
        ERROR("创建临时文件失败: %s", tmp_path);
        fclose(in);
        return -1;
    }

    char line[KEY_SIZE];
    int removed = 0;
    while (fgets(line, sizeof(line), in)) {
        line[strcspn(line, "\r\n")] = '\0';         // 去掉换行
        if (line[0] == '\0') 
        {
            continue;              // 跳过空行
        }
        if (safe_strcmp(line, key) == 0) {          // 命中：不写出，相当于删除
            removed = 1;
            continue;
        }
        fprintf(out, "%s\n", line);
    }

    fflush(out);
    fsync(fileno(out));                              // 尽量落盘
    fclose(in);
    fclose(out);

    if (rename(tmp_path, key_path) != 0) {          // 原子替换
        ERROR("替换 %s 失败 (tmp=%s)", key_path, tmp_path);
        unlink(tmp_path);
        return -1;
    }

    if (!removed) {
        ERROR("未在 %s 中找到要删除的密钥: %.12s...", key_path, key);
        return -1;
    }

    LOG("已从 %s 删除已使用密钥: %.12s...", key_path, key);
    return 0;
}

/* ================= 本地缓存同步 ================= */
/*
功能：确保目录存在
参数：
dir：目录路径
返回值：
0：失败
1：成功
*/
static int ensure_dir(const char *dir) {
    struct stat st;
    if (stat(dir, &st) == 0) return S_ISDIR(st.st_mode);
    if (mkdir(dir, 0755) == 0) return 1;
    ERROR("创建目录失败: %s", dir);
    return 0;
}
/*
功能：复制文件并设置权限
参数：
src：源文件路径
dst：目标文件路径
mode：权限
返回值：
0：失败
1：成功
*/
static int copy_file_with_mode(const char *src, const char *dst, mode_t mode) {
    FILE *in = fopen(src, "rb");
    if (!in) { ERROR("打开源文件失败: %s", src); return 0; }
    FILE *out = fopen(dst, "wb");
    if (!out) { ERROR("创建目标文件失败: %s", dst); fclose(in); return 0; }
    char buf[4096]; size_t n;
    while ((n = fread(buf, 1, sizeof(buf), in)) > 0) {
        if (fwrite(buf, 1, n, out) != n) 
        { 
            ERROR("写入目标文件失败: %s", dst); 
            fclose(in); 
            fclose(out); 
            return 0; 
        }
    }
    fflush(out);
    fchmod(fileno(out), mode);
    fclose(in); fclose(out);
    return 1;
}

/*
功能：更新本地许可证缓存
参数：
usb_path：U盘路径
返回值：
0：失败
1：成功
*/
static int update_local_license_cache(const char *usb_path) {
    if (!usb_path) return 0;
    if (!ensure_dir(LOCAL_LICENSE_DIR)) return 0;
    char src[512];
    snprintf(src, sizeof(src), "%s/%s", usb_path, LICENSE_FILE);
    if (access(src, R_OK) != 0) {
        ERROR("U盘许可证不存在，无法同步: %s", src);
        return 0;
    }
    if (!copy_file_with_mode(src, LOCAL_LICENSE_PATH, 0600)) {
        ERROR("同步本地许可证失败: %s", LOCAL_LICENSE_PATH);
        return 0;
    }
    LOG("已更新本地许可证缓存: %s", LOCAL_LICENSE_PATH);
    return 1;
}

/*
功能：直接按路径验证许可证
参数：
license_path：许可证文件路径
license：许可证结构体
返回值：
0：验证失败
1：验证成功
*/
static int validate_license_at(const char *license_path, License *license) {
    LOG("========= 许可证验证开始 =========");
    LOG("目标文件:%s", license_path);
    FILE *fp = fopen(license_path, "rb");
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

    char *data = (char*)malloc(size);
    if (!data) { ERROR("内存分配失败(%ld字节)", size); fclose(fp); return 0; }
    size_t read_size = fread(data, 1, size, fp);
    fclose(fp);
    if (read_size != (size_t)size) { ERROR("文件读取不完整(%zu/%ld)", read_size, size); free(data); return 0; }

    // 分离 HMAC
    unsigned char stored_hmac[SHA256_DIGEST_LENGTH];
    memcpy(stored_hmac, data + size - SHA256_DIGEST_LENGTH, SHA256_DIGEST_LENGTH);

    unsigned char computed_hmac[SHA256_DIGEST_LENGTH];
    unsigned char key[HMAC_SECRET_SIZE];

    // 获得HMAC解密密钥
    get_hmac_key(key);

    unsigned int maclen = 0;
    // 对设备列表数据计算HMAC
    HMAC(EVP_sha256(), key, HMAC_SECRET_SIZE, (unsigned char*)data, size - SHA256_DIGEST_LENGTH, computed_hmac, &maclen);

    // 比较HMAC
    if (constant_time_memcmp(stored_hmac, computed_hmac, SHA256_DIGEST_LENGTH) != 0) {
        char stored_hex[65]={0}, computed_hex[65]={0};
        for (int i=0;i<SHA256_DIGEST_LENGTH;i++)
        {
            snprintf(stored_hex+i*2,3,"%02x",stored_hmac[i]); 
            snprintf(computed_hex+i*2,3,"%02x",computed_hmac[i]); 
        }
        // 打印HMAC校验失败
        ERROR("HMAC校验失败\n存储值:%s\n计算值:%s", stored_hex, computed_hex);
        free(data);
        return 0;
    }
    LOG("HMAC校验通过");

    // 解析设备列表（\0 分隔），并保存到license结构体中
    if (!license->devices) {
        license->devices = (char**)malloc(MAX_DEVICES * sizeof(char*));
        if (!license->devices) 
        { 
            ERROR("设备列表初始化失败"); 
            free(data); return 0; 
        }
        memset(license->devices, 0, MAX_DEVICES * sizeof(char*));
        license->count = 0;
    }

    char *ptr = data;
    // HMAC位置
    long remain = size - SHA256_DIGEST_LENGTH;
    // 解析设备列表
    while (remain > 0 && license->count < MAX_DEVICES) {
        size_t len = strnlen(ptr, remain);
        if (len == 0) break;
        // 分配内存
        license->devices[license->count] = strndup(ptr, len);
        if (!license->devices[license->count]) 
        { 
            ERROR("设备字符串内存分配失败"); 
            break; 
        }
        // 保存设备
        LOG("加载设备[%d]:%.*s", license->count+1, (int)len, ptr);
        license->count++;
        ptr += len + 1;
        // 剩余长度
        remain -= (len + 1);
    }
    // 释放内存
    free(data);
    LOG("共加载 %d 台设备", license->count);
    return 1;
}

/* ================= 安全保存许可证（数据 + HMAC） ================= */
static int secure_save_license(const char *usb_path, const License *license) {
    if (!usb_path || !license) return 0;

    char path[512];
    snprintf(path, sizeof(path), "%s/%s", usb_path, LICENSE_FILE);

    // 估算数据区大小
    size_t data_sz = 0;
    for (int i = 0; i < license->count; i++) {
        if (license->devices[i]) 
        {
            data_sz += strlen(license->devices[i]) + 1;
        }
    }
    if (data_sz == 0) data_sz = 1;

    // 分配内存
    unsigned char *buf = (unsigned char *)malloc(data_sz);
    if (!buf) 
    { 
        ERROR("secure_save_license: 分配内存失败(%zu)", data_sz); 
        return 0; 
    }

    // 填充设备数据
    size_t off = 0;
    for (int i = 0; i < license->count; i++) {
        if (license->devices[i]) {
            // 获取设备长度
            size_t len = strlen(license->devices[i]);
            // 复制设备数据
            memcpy(buf + off, license->devices[i], len);
            // 偏移
            off += len; 
            buf[off++] = '\0';
        }
    }
    // 如果off为0，则直接设置为结束符
    if (off == 0) buf[off++] = '\0';

    // 计算 HMAC
    unsigned char key[HMAC_SECRET_SIZE];
    get_hmac_key(key);
    unsigned char mac[SHA256_DIGEST_LENGTH]; 
    // HMAC长度
    unsigned int maclen = 0;
    // 计算HMAC
    HMAC(EVP_sha256(), key, HMAC_SECRET_SIZE, buf, off, mac, &maclen);

    // 写文件：数据区 + HMAC
    FILE *fp = fopen(path, "wb");
    if (!fp) 
    { 
        ERROR("secure_save_license: 无法打开文件写入: %s", path); 
        free(buf); 
        return 0; 
    }
    // 写数据区
    if (fwrite(buf, 1, off, fp) != off)
    { 
        ERROR("secure_save_license: 数据区写入失败"); 
        fclose(fp); 
        free(buf);
         return 0; 
    }
    // 写HMAC
    if (fwrite(mac, 1, SHA256_DIGEST_LENGTH, fp) != SHA256_DIGEST_LENGTH) 
    { 
        ERROR("secure_save_license: HMAC 写入失败"); 
        fclose(fp); 
        free(buf); 
        return 0; 
    }
    // 刷新文件
    fflush(fp);
    // 设置权限为 0600
    fchmod(fileno(fp), 0600);
    fclose(fp);
    free(buf);

    LOG("secure_save_license: 许可证已保存到: %s (数据:%zu, HMAC:%d)", path, (size_t)off, SHA256_DIGEST_LENGTH);
    return 1;
}

/* ================= 许可证管理 ================= */
int validate_license(const char *usb_path, License *license) {
    if (!usb_path) {
        ERROR("未找到U盘，无法验证许可证");
        return 0;
    }
    char license_path[512];
    snprintf(license_path, sizeof(license_path), "%s/%s", usb_path, LICENSE_FILE);
    return validate_license_at(license_path, license);
}


/* ================= 主系统初始化 ================= */
int initialize() {
    LOG("\n====== 系统初始化开始 ======\n");

    // 0) 生成硬件指纹（提前生成，供本地/离线验证）
    LOG("正在获取目标硬件指纹(支持 TARGET_HWID_HEX 环境变量)...");
    const char *hwid = get_target_hwid();
    LOG("当前硬件指纹:%s", hwid);

   // 1) 先尝试“主许可证路径”的本地验证（可通过环境变量指向设备路径）
{
    //解析许可证路径
    const char *primary = resolve_primary_license_path();
    // 初始化许可证结构体
    License local = {0};
    // 验证许可证
    if (validate_license_at(primary, &local)) {
        LOG("使用本地许可证验证: %s", primary);
        // 遍历许可证中的设备
        for (int i = 0; i < local.count; i++) {
            // 通过许可证里的设备与硬件指纹对比
            if (local.devices[i] && strcmp(local.devices[i], hwid) == 0) {
                LOG("已在本地许可证中授权，允许离线运行");
                // 释放 local.devices 内存
                // 返回0，表示初始化成功
                return 0;
            }
        }
        LOG("本地许可证存在，但不包含当前 HWID");
        // 这里不 return，继续后续流程（可能走U盘，或直接失败）
    } else {
        LOG("本地许可证不存在或校验失败，路径: %s", primary);
    }
}

    // 是否禁用 U 盘流程（设备上建议设 DISABLE_USB_FLOW=1）
    const char *disable_usb = getenv("DISABLE_USB_FLOW");
    if (disable_usb && strcmp(disable_usb, "1") == 0) 
    {
        ERROR("本地许可证无效且禁用了U盘流程，初始化失败");
        return -1;
    }

    // 2) 检测U盘（保持你原有逻辑）
    const char *usb_path = find_usb_drive();
    if (!usb_path) {
        ERROR("未找到U盘，无法继续操作");
        return -1;
    }
    LOG("U盘挂载点: %s", usb_path);

    License license = {0};
    int ret = 0;

    // 3) 验证 U盘 中的许可证
    LOG("正在验证U盘中的许可证文件...");
    if (!validate_license(usb_path, &license)) {
        LOG("创建新的许可证文件");
        license.devices = (char**)malloc(MAX_DEVICES * sizeof(char*));
        if (!license.devices) 
        { 
            ERROR("设备列表初始化失败"); 
            return -1; 
        }
        memset(license.devices, 0, MAX_DEVICES * sizeof(char*));
        license.count = 0;
    }

    // 4) 检查是否已注册
    LOG("检查注册状态(已注册设备数:%d)", license.count);
    int registered = 0;
    for (int i = 0; i < license.count; i++) {
        // 通过许可证里的设备与硬件指纹对比
        if (license.devices[i] && strcmp(license.devices[i], hwid) == 0) {
            LOG("设备已注册");
            registered = 1;
            break;
        }
    }

    // 如果未注册，则执行密钥验证流程
    if (!registered) {
        // 如果许可证里的设备数量已达上限，则返回错误
        if (license.count >= MAX_DEVICES) {
            ERROR("设备数量已达上限(最大:%d)", MAX_DEVICES);
            ret = -1;
        } else {
            LOG("执行密钥验证流程...");
            // 初始化密钥数组
            char valid_keys[TOTAL_KEYS][KEY_SIZE] = {0};
            int max_keys = TOTAL_KEYS;
            int key_count = load_usb_keys(usb_path, valid_keys, &max_keys);
            // 如果密钥加载失败或无可用密钥，则返回错误
            if (key_count <= 0) {
                ERROR("密钥加载失败或无可用密钥");
                ret = -1;
            } else {
                // 选第一条可用密钥（可改成随机）
                const char *selected_key = NULL;
                int selected_idx = -1;
                for (int i = 0; i < key_count; i++) {
                    if (valid_keys[i][0] != '\0') 
                    { 
                        selected_key = valid_keys[i];
                        selected_idx = i; 
                        break; 
                    }
                }
                if (!selected_key) {
                    ERROR("未找到可用密钥");
                    ret = -1;
                } else {
                    // 先把本机 HWID 加进 license
                    license.devices[license.count] = strdup(hwid);
                    if (!license.devices[license.count]) {
                        ERROR("设备信息存储失败");
                        ret = -1;
                    } else {
                        license.count++;
                        LOG("新设备注册成功(当前总数:%d)", license.count);

                        // 先安全保存 license
                        if (!secure_save_license(usb_path, &license)) {
                            ERROR("许可证保存失败");
                            ret = -1;
                        } else {
                            // license 持久化成功后，再真正“消费”这条密钥：从 valid_keys.dat 删除它
                            if (record_used_key(usb_path, selected_key) != 0) {
                                ERROR("从 valid_keys.dat 删除密钥失败");
                                ret = -1;
                            } else {
                                LOG("已消费密钥: %.12s...", selected_key);
                            }
                        }
                    }
                }
            }
        }
    } else {
        LOG("设备已注册，跳过注册流程");
    }

    // 5) 若此轮通过了 U盘验证/注册，则同步一份到本地，供下次离线验证
    if (ret == 0 && usb_path) update_local_license_cache(usb_path);

    // 清理内存
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

int main(){
    printf("\n====== 程序启动 ======\n");
    int result = initialize();
    printf("初始化结果:%s\n", result == 0 ? "成功" : "失败");
    return result;
}
