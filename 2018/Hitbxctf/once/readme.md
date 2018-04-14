根据动态调试可知addr段中初始值为&data,先通过edit函数将往data开始的bss中写入p64(1)+p64(0x20fe1)+p64(main_arena-0x10)*2，前两项是为了后面重写main_arena做size大小准备

    int edit()
    {
      if ( is_edit == 1 )
    		return -1;
      read_buf(addr, 0x20LL);   
      is_edit = 1;
      return puts("success.");
    }

写完后再利用add和exchange函数将main_arena指向data,此后再进行分配堆块就是从data开始分配了

    _int64 add()
    {
      _QWORD *v0; // rax
      _QWORD *v1; // ST10_8
    
      v0 = malloc(0x20uLL);
      v0[2] = 0LL;
      v0[3] = 0LL;
      v1 = addr;
      addr = v0;
      v0[2] = &data;
      v0[3] = v1;
      v1[2] = v0;
      puts("suceess.");
      return 0LL;
    }

    int exchange()
    {
      if ( dword_562993DB6060 == 1 )
    return -1;
      addr = (void *)*((_QWORD *)addr + 3);
      *((_QWORD *)addr + 2) = &data;
      dword_562993DB6060 = 1;
      return puts("success.");
    }

此时进入game函数分配一个合适大小的堆块，然后在堆块中写入数据，写入的数据既可以将addr的值覆盖为free_hook的值，将ptr覆盖为binsh_addr,又可以将is_edit域的值重写为0

做完这一切，再一次调用edit函数，将free_hook改写为system

最后执行game函数中的free，便可以get shell了