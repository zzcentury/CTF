最后才看到flag知道那个是base64..(我好菜）

因为edit函数中写入的size是根据strlen来的，所以可以造成off-by-one

申请两个堆块，在第一个堆块中伪造一个fake_chunk并利用off-by-one改写第二个堆块的size域，再free掉第二个chunk，触发double_free

再将free_hook改写为printf,以后就相当于调用print了，于是这题就变为格式化字符串漏洞来做了。。。。。

先泄露libc地址，再利用格式化将exit@got改写为one_gadget,最后调用exit就可以get shell了。

不知为啥开始的时候直接将free_hook覆盖为one_gadget不行