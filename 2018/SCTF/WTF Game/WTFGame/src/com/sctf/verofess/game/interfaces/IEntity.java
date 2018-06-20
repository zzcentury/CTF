package com.sctf.verofess.game.interfaces;

public interface IEntity {
    int GetHP();
    int GetAttack();
    long GetDataStoreAddress();
    boolean CheckCommand(String Command);
}
