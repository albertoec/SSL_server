
import java.io.BufferedReader;
import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
/**
 *
 * @author eryalus
 */
public class Killer extends Thread {

    private final BufferedReader br;
    private Thread hilo = null;

    public Killer(BufferedReader br) {
        this.br = br;
    }

    @Override
    public void run() {
        while (true) {
            try {
                String line = br.readLine();
                if (line.equalsIgnoreCase("exit")) {
                    System.exit(0);
                }
            } catch (IOException ex) {
                Logger.getLogger(Killer.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public void Start() {
        if (hilo == null) {
            hilo = new Thread(this, "Hilo killer");
            hilo.start();
        }
    }

}
