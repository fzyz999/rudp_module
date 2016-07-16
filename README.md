# rudp_module #
该项目实现了一个可以进行可靠传输的内核模块。该模块将注册/proc/net/rudp_server文件，
并通过该文件与用户空间进行信息交互。读该文件代表接收消息，写该文件代表发送消息。

# 文件说明 #
compile.sh	编译测试用的脚本。
drop.sh		调用NetEm模块模拟丢包，以测试可靠通信。
test.sh		可靠通信测试脚本，依次发送数字1~10。
rudpsock.c	源文件
