## 改造

### 参数相关

#### 冗余命令去除
可以看到有很多我们实际不需要的子命令
![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250223202022.png)

本质是用了`cobra`框架作为命令的脚手架，只需要删除对应目录下添加子命令的代码即可。
如`admin.go`添加了`reload、status、stop`三个子命令，将文件删除后即可。
![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250223202321.png)

删除冗余的子命令后，结果如下
![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250223202517.png)

#### 冗余介绍改造
* 如上图所示，将对应的参数对应的介绍改的答非所问，从而降低语义识别方面的特征。


![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250224200422.png)




### 删除特征

#### 日志
即把所有相关输出的日志均注释

#### 字段

其实修改意义不大 高版本默认开启tls

`pkg/msg/msg.go`

先改字段名
```go
// When frpc start, client send this message to login to server.  
type Login struct {  
    Version      string            `json:"version,omitempty"`  
    Hostname     string            `json:"hostname,omitempty"`  
    Os           string            `json:"os,omitempty"`  
    Arch         string            `json:"arch,omitempty"`  
    User         string            `json:"user,omitempty"`  
    PrivilegeKey string            `json:"privilege_key,omitempty"`  
    Timestamp    int64             `json:"timestamp,omitempty"`  
    RunID        string            `json:"run_id,omitempty"`  
    Metas        map[string]string `json:"metas,omitempty"`  
  
    // Currently only effective for VirtualClient.  
    ClientSpec ClientSpec `json:"client_spec,omitempty"`  
  
    // Some global configures.  
    PoolCount int `json:"pool_count,omitempty"`  
}


type LoginResp struct {  
    Version string `json:"version,omitempty"`  
    RunID   string `json:"run_id,omitempty"`  
    Error   string `json:"error,omitempty"`  
}

```
改成如下：
![](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250223215801.png)

流量如下：
![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250223215743.png)

#### 版本号

`/pkg/util/version/version.go`
![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250223220625.png)
![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250223220658.png)


#### tls默认字节配置

从 v0.25.0 版本开始 FRPC 和 FRPS 之间支持通过 TLS 协议加密传输，为了端口复用，FRP 建立 TLS 连接的第一个字节为 `0x17` ，有些流量识别程序识别到特定流量，可能会阻拦，故我们可以对其进行修改。

功能点在 `pkg/util/net/tls.go` 文件中修改，如下：

```go
……
// var FRPTLSHeadByte = 0x17
// 修改为下方，可自定义其它
var FRPTLSHeadByte = 0x88

func CheckAndEnableTLSServerConnWithTimeout(
    c net.Conn, tlsConfig *tls.Config, tlsOnly bool, timeout time.Duration,
) (out net.Conn, isTLS bool, custom bool, err error) {
    sc, r := gnet.NewSharedConnSize(c, 2)
    buf := make([]byte, 1)
    var n int
    _ = c.SetReadDeadline(time.Now().Add(timeout))
    n, err = r.Read(buf)
    _ = c.SetReadDeadline(time.Time{})
    if err != nil {
        return
    }
……
```

该方式在新版本中可在客户端配置中加入 `disable_custom_tls_first_byte = true` 参数使得 TLS 不发送 `0x17` 。

### 远程加载配置文件

先增加`-r`参数
![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250223210845.png)
增加远程下载配置的函数

```go
func downloadConfigFile(url string) (string, error) {  
    resp, err := http.Get(url)  
    if err != nil {  
       return "", fmt.Errorf("failed to download config file: %w", err)  
    }  
    defer resp.Body.Close()  
  
    if resp.StatusCode != http.StatusOK {  
       return "", fmt.Errorf("failed to download config file: status code %d", resp.StatusCode)  
    }  
  
    tempFile, err := os.CreateTemp("", "Windows-Remote-Config.ini")  
    if err != nil {  
       return "", fmt.Errorf("failed to create temp file: %w", err)  
    }  
    defer tempFile.Close()  
  
    _, err = io.Copy(tempFile, resp.Body)  
    if err != nil {  
       return "", fmt.Errorf("failed to write to temp file: %w", err)  
    }  
  
    return tempFile.Name(), nil  
}
```

填充针对`cfgUrl`的处理逻辑，远程获取到对应文件后，赋值给`cfgFile`，令其去创建操作文件。
![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250223210929.png)



### 配置文件自动删除

功能点在 `cmd/frpc/sub/root.go` 文件中修改。原理是在 `init` 中注册参数，然后判断参数是否开启，开启就删除。代码如下：
![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250224152002.png)

魔改`runClient`方法，支持根据传入`delEnable`判断是否删除配置文件

![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250224155801.png)



### frpc远程连接 时加密配置文件中的服务端IP

支持针对配置文件字段中`serverAddr`字段的加密处理，加密手法支持RC4、AES



客户端`frpc`连接客户端的代码，在客户端第一次登录，去访问服务器，在`client/connector.go:realConnect()`方法中，调用栈详情查看栈中红线部分。

![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250224165748.png)

`c.cfg.ServiceAddr`赋值在配置文件中的`serverAddr`字段

![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250224170213.png)


在`pkg/dscrypto/aes.go`中编写相关AES加解密相关的代码

```go  
package dscrypto  
  
import (  
    "bytes"  
    "crypto/aes"    "crypto/cipher"    "encoding/base64"    "fmt")  
  
func AesEncrypt(orig string, key string) string {  
    // 转成字节数组  
    origData := []byte(orig)  
    k := []byte(key)  
  
    // 分组秘钥  
    block, _ := aes.NewCipher(k)  
    // 获取秘钥块的长度  
    blockSize := block.BlockSize()  
    // 补全码  
    origData = PKCS7Padding(origData, blockSize)  
    // 加密模式  
    blockMode := cipher.NewCBCEncrypter(block, k[:blockSize])  
    // 创建数组  
    cryted := make([]byte, len(origData))  
    // 加密  
    blockMode.CryptBlocks(cryted, origData)  
  
    return base64.StdEncoding.EncodeToString(cryted)  
  
}  
  
func AesDecrypt(cryted string, key string) string {  
    // 转成字节数组  
    crytedByte, _ := base64.StdEncoding.DecodeString(cryted)  
    k := []byte(key)  
  
    // 分组秘钥  
    block, _ := aes.NewCipher(k)  
    // 获取秘钥块的长度  
    blockSize := block.BlockSize()  
    // 加密模式  
    blockMode := cipher.NewCBCDecrypter(block, k[:blockSize])  
    // 创建数组  
    orig := make([]byte, len(crytedByte))  
    // 解密  
    blockMode.CryptBlocks(orig, crytedByte)  
    // 去补全码  
    orig = PKCS7UnPadding(orig)  
    return string(orig)  
}  
  
// PKCS7Padding 补码  
func PKCS7Padding(ciphertext []byte, blocksize int) []byte {  
    padding := blocksize - len(ciphertext)%blocksize  
    padtext := bytes.Repeat([]byte{byte(padding)}, padding)  
    return append(ciphertext, padtext...)  
}  
  
// PKCS7UnPadding 去码  
func PKCS7UnPadding(origData []byte) []byte {  
    length := len(origData)  
    unpadding := int(origData[length-1])  
    return origData[:(length - unpadding)]  
}
```

在`pkg/dscrypto/var.go`中指定相关的加密秘钥，
`VpsIP` 即为实际客户端需要连接的服务IP
`AESKey`为加密秘钥，来自`fprs`的md5hash

![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250224170547.png)

```go
package dscrypto  
  
// 对服务器IP进行隐藏需要修改此处的AESKey和AESencryptCode。  
// 同时需要对frpc.ini中的server_addr进行修改，修改成AESencryptCode。  
// server_addr支持正常的ip和加密之后的ip，2种形式。  
var (  
    VpsIP  = "172.26.216.10" //修改成自己的vps IP地址  
    AESKey = "d05b1335ffe14d6b5d058272462b39c5"  
  
    AESencryptCode = "Kpm7EaI0b+VflSpyZOp3Lg=="  
    //AESencryptCode = "2HrQDAPV5JgjckfYkO9u4g=="  
)
```


配置文件编写如下:
```text
serverAddr = "Kpm7EaI0b+VflSpyZOp3Lg=="
serverPort = 7000

[[proxies]]
name = "test-tcp"
type = "tcp"
localIP = "127.0.0.1"
localPort = 22
remotePort = 6000
```

即可客户端看不到命令行

#### 配置文件加密

参考： https://github.com/CodeSecurityTeam/frp
与加密服务端IP的套路一样，无非就是对整个文件进行加密，然后在客户端读取加密文件，然后进行解密，对解密的文件进行逐个字段提取。

#### 原生的配置

frp 在高于0.50.0版本已经默认支持是开启tls_enable参数
数据流已经是加密的

![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250224171218.png)
已经无法看到明文的信息



### 会话消息加密
Important!

实现逻辑依然在`client/service.go/NewControl()`方法
在上述通过`svr.login()`方法进行服务端认证之后，会通过`NewControl`方法生成控制器。
并且默认除了`ssh-tunnel`类型外， 默认的`connEncrypted`为`true`
![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250224193545.png)

在`NewControl`方法中，由于`ConnEncrypted`为`True`，因此通过`NewCryptoReaderWriter`方法创建加密的writer和reader。

![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250224193600.png)
![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250224193809.png)

加密器传入的秘钥来自`sessionCtx.Common.Auth.Token`，通过查看相关数据结构，发现其来自配置文件中`auth.token`对应的赋值。
![](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250224194351.png)

通过查看`NewReader`和`NewReader`的代码，可以发现使用的加密手段为`AES-128-CFB`。
默认使用的加密的`salt`为`crypto`，可以在对应的`service.go`中`init()`方法，修改`crypto.DefaultSalt `
![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250224193900.png)


![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250224194106.png)


因此如果使用`frp`作为黑客工具进行利用，
* 考虑到安全问题，可能需要修改默认的`Token`,加密所需的`salt`，或者AES算法进行优化。
* 最简单的就是将`Token`及`salt`进行赋值，复杂化。
* 并且为了保证加密双方客户端和服务端均可正常加解密通信，因此`frpc`和`frps`中涉及加密部分对应的均需改造成相同的数值。

![image.png](https://cnblog-img-reus09.oss-cn-beijing.aliyuncs.com/obidian/20250224195234.png)

