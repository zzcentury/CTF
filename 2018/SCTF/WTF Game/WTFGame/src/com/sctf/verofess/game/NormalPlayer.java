package com.sctf.verofess.game;

import com.sctf.verofess.blackmagic.FastArray;
import com.sctf.verofess.game.interfaces.IEntity;

public class NormalPlayer implements IEntity {
    private FastArray DataStore = new FastArray(3);

    public NormalPlayer(){
        DataStore.PutIntData(0, Integer.MIN_VALUE);
        DataStore.PutIntData(1, Integer.MIN_VALUE);
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
        return DataStore.GetIntData(1);
    }

    @Override
    public long GetDataStoreAddress() {
        return DataStore.GetPointer();
    }

    @Override
    public boolean CheckCommand(String Command) {
        return false;
    }

    @Override
    public String toString(){
        return this.GetHP() + "-" + this.GetAttack();
    }
}
