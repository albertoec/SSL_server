/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Utils.DB;

/**
 *
 * @author eryalus
 */
public class DBData {

    

    private String ruta, nombre, usuario, sello;
    private boolean confidencialidad;
    private byte[] firma_cliente, firma_servidor;
    private long id;

    public String getRuta() {
        return ruta;
    }

    public void setRuta(String ruta) {
        this.ruta = ruta;
    }

    public String getNombre() {
        return nombre;
    }

    public void setNombre(String nombre) {
        this.nombre = nombre;
    }

    public String getUsuario() {
        return usuario;
    }

    public void setUsuario(String usuario) {
        this.usuario = usuario;
    }

    public String getSello() {
        return sello;
    }

    public void setSello(String sello) {
        this.sello = sello;
    }

    public boolean getConfidencialidad() {
        return confidencialidad;
    }

    public void setConfidencialidad(boolean confidencialidad) {
        this.confidencialidad = confidencialidad;
    }

    public byte[] getFirma_cliente() {
        return firma_cliente;
    }

    public void setFirma_cliente(byte[] firma_cliente) {
        this.firma_cliente = firma_cliente;
    }

    public byte[] getFirma_servidor() {
        return firma_servidor;
    }

    public void setFirma_servidor(byte[] firma_servidor) {
        this.firma_servidor = firma_servidor;
    }
    
    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

}
