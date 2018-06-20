package com.sctf.verofess.game;

import com.sctf.verofess.blackmagic.FastArray;
import com.sctf.verofess.game.interfaces.IEntity;

public class VIPPlayer implements IEntity {
    private FastArray DataStore = new FastArray(3);

    public VIPPlayer(){
        DataStore.PutIntData(0, Integer.MIN_VALUE);
        DataStore.PutIntData(1, Integer.MIN_VALUE);
    }

    public void SetHP(int HP){
        DataStore.PutIntData(0, HP);
    }


    public void SetATK(int ATK){
        DataStore.PutIntData(1, ATK);
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
        return true;//Oh! VIP! YOU CAM DO ANY THING!
    }

    @Override
    public String toString(){
        return (this.GetHP() + "-" + this.GetAttack());
    }
}
