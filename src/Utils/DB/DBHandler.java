/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Utils.DB;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author eryalus
 */
public class DBHandler {

    private static final String NOMBRE_DB = "seguridad", IP = "127.0.0.1", USER = "seguridad", PASSWD = "", PORT = "", TIMEOUT = "15000";
    private Connection conn;

    /**
     * Crea el handler de la base de datos.
     *
     * @throws DBException
     */
    public DBHandler() throws DBException {
        try {
            crearBaseDatos();
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException ex) {
            DBException except = new DBException("No se ha podido crear la base de datos.");
            except.setStackTrace(ex.getStackTrace());
            throw except;
        }

    }

    /**
     * Crea un statement para poder realizar acciones en la base de datos
     *
     * @return Statement
     * @throws SQLException En cas de no poder crear el statement
     */
    private Statement getStat() throws SQLException {
        Statement stat;
        try {
            stat = conn.createStatement();
        } catch (SQLException ex) {
            stat = conn.createStatement();
        }
        return stat;
    }

    public int newEntry(String ruta, String nombre_doc, String sello, byte[] firma_cliente, byte[] firma_servidor, boolean confidencialidad, String usuario) {
        try{
            Statement st = getStat();
            st.execute("INSERT INTO datos(ruta_doc,nombre_doc,sello,firma_cliente,firma_server,confidencialidad,usuario) VALUES('"+ruta+"','"+nombre_doc+"','"+sello+"',NULL,NULL,"+confidencialidad+",'"+usuario+"')");
        } catch (SQLException ex) {
            Logger.getLogger(DBHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        
        return -1;
    }

    /**
     * Crea la base de datos e inicializa las tablas e caso de no existir.
     *
     * @return true si todo ha ido bien o falso en otro caso.
     */
    private void crearBaseDatos() throws SQLException, ClassNotFoundException, InstantiationException, IllegalAccessException {
        conn = MySQLConnection(USER, PASSWD, PORT, "");
        conn.createStatement().execute("CREATE DATABASE IF NOT EXISTS " + NOMBRE_DB);
        conn.close();
        conn = MySQLConnection(USER, PASSWD, PORT, NOMBRE_DB);
        conn.createStatement().execute("CREATE TABLE IF NOT EXISTS datos(id_registro BIGINT NOT NULL AUTO_INCREMENT,ruta_doc TEXT,nombre_doc TEXT,sello TEXT,firma_cliente BLOB,firma_server BLOB,confidencialidad boolean,usuario TEXT,PRIMARY KEY (id_registro))");
    }

    /**
     * Crea una conexión con la base de datos dada.
     *
     * @param user usuario
     * @param pass contraseña
     * @param db_name nombre de la base de datos a conectar
     * @return Conexión
     * @throws ClassNotFoundException
     * @throws SQLException
     */
    private static Connection MySQLConnection(String user, String pass, String port, String db_name) throws ClassNotFoundException, SQLException, InstantiationException, IllegalAccessException {
        Class.forName("com.mysql.jdbc.Driver").newInstance();
        Connection conn;
        if (port.equals("")) {
            conn = DriverManager.getConnection("jdbc:mysql://" + IP + "/" + db_name + "?connectTimeout=" + TIMEOUT, user, pass);
        } else {
            conn = DriverManager.getConnection("jdbc:mysql://" + IP + ":" + port + "/" + db_name + "?connectTimeout=" + TIMEOUT, user, pass);
        }
        return conn;
    }
}
