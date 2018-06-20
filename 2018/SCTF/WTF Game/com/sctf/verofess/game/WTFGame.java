package com.sctf.verofess.game;

import com.sctf.verofess.blackmagic.FastArray;
import com.sctf.verofess.game.interfaces.IEntity;

public class WTFGame {
    private static Boss boss = new Boss();

    private IEntity Player = null;

    public String PraseCommand(String Command){
        if(Command.equalsIgnoreCase("CreatePlayer")){
            this.Player = new NormalPlayer();
            return "OK!";
        }

        if(Command.equalsIgnoreCase("VeroFessIsHandsome")){
            this.Player = new VIPPlayer();
            return "OK!";
        }

        if(Command.equalsIgnoreCase("ShowInfo")){
            if(this.Player != null && this.Player.CheckCommand(Command)){
                return this.Player.toString();
            }
        }

        if(Command.startsWith("SetHP")){
            if(this.Player != null && this.Player.CheckCommand(Command)){
                int Number = Integer.decode(Command.split("#")[1]);
                ((VIPPlayer)this.Player).SetHP(Number);
                 return "OK!";
            }
        }

        if(Command.startsWith("SetATK")){
            if(this.Player != null && this.Player.CheckCommand(Command)){
                int Number = Integer.decode(Command.split("#")[1]);
                ((VIPPlayer)this.Player).SetATK(Number);
                return "OK!";
            }
        }

        if(Command.equalsIgnoreCase("SwapWithBoss")){
            if(this.Player != null && this.Player.CheckCommand(Command)){
                ((VIPPlayer)this.Player).setDataStore(new FastArray(WTFGame.boss.GetDataStoreAddress()));
                WTFGame.boss.setDataStore(new FastArray(((VIPPlayer) this.Player).GetDataStoreAddress()));
                return "OK!";
            }
        }

        if(Command.equalsIgnoreCase("GetFlag")){
            if(this.Player != null && this.Player.CheckCommand(Command)){
                return "FLAG!";
            }
        }

        if(Command.equalsIgnoreCase("Attack")){
            if(((IEntity)this.Player).GetAttack() > Integer.MAX_VALUE && ((IEntity)this.Player).GetHP() > Integer.MAX_VALUE){
                return (new FLAG()).toString();
            }
        }

        if(Command.equalsIgnoreCase("Save")){
            if(this.Player != null && this.Player.CheckCommand(Command)){
                return (new Save(this.Player, WTFGame.boss)).toString();
            }
        }

        if(Command.equalsIgnoreCase("DebugShowDataStoreAddress")){
            if(this.Player != null && this.Player.CheckCommand(Command)){
                return Long.toString((this.Player).GetDataStoreAddress());
            }
        }

        if(Command.startsWith("DebugSetDataStoreAddress")){
            if(this.Player != null && this.Player.CheckCommand(Command)){
                long Address = Long.decode(Command.split("#")[1]);
                ((VIPPlayer)this.Player).setDataStore(new FastArray(Address));
                return "OK!";
            }
        }

        return "Error!";
    }
}
