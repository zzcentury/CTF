package com.sctf.verofess.blackmagic;

public class FastArray {
    private UnsafeWapper unsafeWapper = new UnsafeWapper();
    private long ArrayPointer = 0;

    public FastArray(int ArraySize) {
        ArrayPointer = unsafeWapper.AllocMemory(4 * ArraySize);
    }

    public FastArray(long OldArrayPointer) {
        this.ArrayPointer = OldArrayPointer;
    }

    public int GetIntData(int Index) {
        return unsafeWapper.ReadIntData(ArrayPointer + 4 * Index);
    }

    public void PutIntData(int Index, int Data) {
        unsafeWapper.PutIntData(ArrayPointer + 4 * Index, Data);
    }

    public long GetPointer() {
        return ArrayPointer;
    }
}
