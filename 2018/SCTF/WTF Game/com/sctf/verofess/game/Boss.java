package com.sctf.verofess.game;

import com.sctf.verofess.blackmagic.FastArray;
import com.sctf.verofess.game.interfaces.IEntity;

public class Boss implements IEntity {
    private FastArray DataStore = new FastArray(3);

    public Boss(){
        DataStore.PutIntData(0, Integer.MAX_VALUE);
        DataStore.PutIntData(1, Integer.MAX_VALUE);
    }

    public void setDataStore(FastArray dataStore) {
        DataStore = dataStore;
    }

    @Override
    public int GetHP() {
        return DataStore.GetIntData(0);
    }

    @Override
    public int GetAttack() {
        return DataStore.GetIntData(0);
    }

    @Override
    public long GetDataStoreAddress() {
        return DataStore.GetPointer();
    }

    @Override
    public boolean CheckCommand(String Command) { // Boss Can Do ANYTHING
        return true;
    }

    @Override
    public String toString(){ //Boss Know Every Thing
        return (Integer.toHexString(this.GetHP()) + "|" + Integer.toHexString(this.GetAttack()) + "|"+ (new FLAG()).toString());
    }
}
