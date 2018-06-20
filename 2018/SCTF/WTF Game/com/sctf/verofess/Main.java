package com.sctf.verofess;

import com.sctf.verofess.game.WTFGame;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

public class Main {
    public static void main(String[] args) {
        WTFGame GameInstance = new WTFGame();
        BufferedReader _BufferedReader = new BufferedReader(new InputStreamReader(System.in));

        System.out.println("Do you like van you xi? Type your command!");
        System.out.println("P.S.: Buy VIP J!U!S!T! need 99999.99$!");

        String Command = "";

        while(!Command.equalsIgnoreCase("Exit")){
            System.out.print(">");
            try {
                Command = _BufferedReader.readLine();
            } catch (IOException e) {
                e.printStackTrace();
            }
            System.out.println(GameInstance.PraseCommand(Command));
        }
    }
}
