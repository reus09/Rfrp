/*
0 error(s),0 warning(s)
Team:0e0w Security Team
Author:0e0wTeam[at]gmail.com
Datetime:2022/11/17 16:36
*/

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
