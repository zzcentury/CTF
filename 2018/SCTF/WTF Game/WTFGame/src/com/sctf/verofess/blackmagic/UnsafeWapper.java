package com.sctf.verofess.blackmagic;

import sun.misc.Unsafe;

import java.lang.reflect.Field;

public class UnsafeWapper {
    private static Unsafe UnsafeInstance = UnsafeWapper.GetUnsafeInstance();

    private static Unsafe GetUnsafeInstance() {
        try {
            Field TheUnsafeField = Unsafe.class.getDeclaredField("theUnsafe");
            TheUnsafeField.setAccessible(true);
            return (Unsafe) TheUnsafeField.get(null);
        } catch (Exception e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    public static Unsafe getUnsafeInstance() {
        return UnsafeInstance;
    }

    public long AllocMemory(long ArrayByteSize) {
        return UnsafeInstance.allocateMemory(ArrayByteSize);
    }

    public int ReadIntData(long BasicAddress) {
        return UnsafeInstance.getInt(BasicAddress);
    }

    public void PutIntData(long BasicAddress, int Data) {
        UnsafeInstance.putInt(BasicAddress, Data);
    }
}
