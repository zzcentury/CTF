package com.sctf.verofess.game;

import com.sctf.verofess.blackmagic.FastArray;
import com.sctf.verofess.blackmagic.UnsafeWapper;

public class Save { // Useless Class
    private static Object helperArray[] = new Object[1];
    private static FastArray SaveArray = new FastArray(6);

    public Save (String SavedData){

    }

    public Save(Object Player, Object Boss) {
        helperArray[0] = Player;
        SaveArray.PutIntData(0, UnsafeWapper.getUnsafeInstance().getInt(helperArray, UnsafeWapper.getUnsafeInstance().arrayBaseOffset(Object[].class)));
        helperArray[0] = Boss;
        SaveArray.PutIntData(1, UnsafeWapper.getUnsafeInstance().getInt(helperArray, UnsafeWapper.getUnsafeInstance().arrayBaseOffset(Object[].class)));
    }

    @Override
    public String toString(){
        return SaveArray.GetIntData(0) + "-" + SaveArray.GetIntData(1);
    }
}
