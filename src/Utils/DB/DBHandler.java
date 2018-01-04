/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Utils.DB;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.sql.Blob;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.logging.Level;
import java.util.logging.Logger;

import javax.xml.bind.DatatypeConverter;

/**
 * Handler de la base de datos del proyecto.
 *
 * @author eryalus
 */
public class DBHandler {

    private static final String NOMBRE_DB = "seguridad", IP = "127.0.0.1", USER = "seguridad", PASSWD = "", PORT = "", TIMEOUT = "15000";
    private Connection conn;

    /**
     * Crea el handler de la base de datos.
     *
     * @throws DBException generada al no poder conectarse con la base de datos
     */
    public DBHandler() throws DBException {
        try {
            crearBaseDatos();
        } catch (SQLException | ClassNotFoundException | InstantiationException | IllegalAccessException ex) {
            ex.printStackTrace();
            DBException except = new DBException("No se ha podido crear la base de datos.");
            except.setStackTrace(ex.getStackTrace());
            throw except;
        }

    }

    /**
     * Obtiene el siguiente ID a registrar
     *
     * @return el sigueinte id a registrar o -1L en caso de haber algún problema
     */
    public Long getNextID() {
        long id = -1L;
        try {
            Statement st = getStat();
            ResultSet pub = st.executeQuery("SELECT id_registro FROM datos");
            long last = 0L;
            /**
             * recorremos todos los id_registro mirando si es mayor que el
             * alamcenado y en caso de ser así se alamcena de forma temporal
             */
            while (pub.next()) {
                long temp = pub.getLong("id_registro");
                if (temp > last) {
                    last = temp;
                }
            }
            id = last + 1;
        } catch (SQLException ex) {
            Logger.getLogger(DBHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        return id;
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
            /**
             * se vuelve a realizar el intento por la posible excepcion por
             * timeout, que en caso de saltar al vovler a crear el statement no
             * habría problema y se crearía correctamente
             */
            stat = conn.createStatement();
        }
        return stat;
    }

    /**
     * Carga el listado de los documentos no confidenciales y los confidenciales
     * correspondientes a ese usuario
     *
     * @param usuario Usuario del que se quiere el lisatdo
     * @return HashMap con dos ArrayList uno con el key "confidencial" para los
     * confidenciales y otro "noconfidencial" con los no confidenciales. null en
     * caso de no poder obtener el listado.
     */
    public HashMap<String, ArrayList<DBData>> getListado(String usuario) {
        HashMap<String, ArrayList<DBData>> datos = new HashMap<>();
        ArrayList<DBData> publicos = new ArrayList<>(), confidenciales = new ArrayList<>();

        try {
            Statement st = getStat();
            // Se cargan los no confidenciales
            ResultSet pub = st.executeQuery("SELECT id_registro FROM datos WHERE confidencialidad=false");
            while (pub.next()) {
                publicos.add(getData(pub.getLong("id_registro")));
            }
            // Se cargan los confidenciales asociados a ese usuario
            pub = st.executeQuery("SELECT id_registro FROM datos WHERE confidencialidad=true and usuario='" + usuario + "'");
            while (pub.next()) {
                confidenciales.add(getData(pub.getLong("id_registro")));
            }
            datos.put("noconfidenciales", publicos);
            datos.put("confidenciales", confidenciales);
            return datos;
        } catch (SQLException ex) {
            Logger.getLogger(DBHandler.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    /**
     * Carga los datos para ese id de registro
     *
     * @param id_registro El id de registro del que se quieren obtener los datos
     * @return los datos del registro o null en caso de no existir datos para
     * ese id
     */
    public DBData getData(long id_registro) {
        try {
            Statement st = getStat();
            ResultSet res = st.executeQuery("SELECT * FROM datos WHERE id_registro=" + id_registro);
            DBData datos = new DBData();
            if (res.next()) {
                //cargamos el idRegistro
                datos.setId(id_registro);
                //cargamos la firma del servidor
            	datos.setFirma_servidor(DatatypeConverter.parseBase64Binary(res.getString("firma_server")));
                //cargamos la firma del cliente
                datos.setFirma_cliente(DatatypeConverter.parseBase64Binary(res.getString("firma_cliente")));
                //nombre del doc
                datos.setNombre(res.getString("nombre_doc"));
                //nombre de usuario
                datos.setUsuario(res.getString("usuario"));
                //confidencialidad
                datos.setConfidencialidad(res.getBoolean("confidencialidad"));
                //sello temporal
                datos.setSello(res.getString("sello"));
                //ruta
                datos.setRuta(res.getString("ruta_doc"));
                return datos;
            }

        } catch (SQLException  ex) {
        	ex.printStackTrace();
            return null;
        }
        return null;
    }

    /**
     * Borra la entrada asociada a ese id_registro
     *
     * @param id_registro
     * @return
     */
    public boolean deleteEntry(long id_registro) {
        try {
            Statement st = getStat();
            st.execute("DELETE FROM datos WHERE id_registro=" + id_registro);
            return true;
        } catch (SQLException ex) {
            return false;
        }
    }

    /**
     * Añade una nueva entrada a la tabla
     *
     * @param id_registro
     * @param ruta
     * @param nombre_doc
     * @param sello
     * @param firma_cliente
     * @param firma_servidor
     * @param confidencialidad
     * @param usuario
     * @return true en caso de añadirse correctamente false en caso contrario
     */
    public boolean newEntry(Long id_registro, String ruta, String nombre_doc, String sello, byte[] firma_cliente, byte[] firma_servidor, boolean confidencialidad, String usuario) {
        try {
            Statement st = getStat();
            st.execute("INSERT INTO datos VALUES(" + id_registro + ",'" + ruta + "','" + nombre_doc + "','" + sello + "','" + DatatypeConverter.printBase64Binary(firma_cliente) + "','" + DatatypeConverter.printBase64Binary(firma_servidor) + "'," + confidencialidad + ",'" + usuario + "')");
            return true;
        } catch (SQLException ex) {
            return false;
        }
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
        conn.createStatement().execute("CREATE TABLE IF NOT EXISTS datos(id_registro BIGINT NOT NULL,ruta_doc varchar(1000),nombre_doc varchar(100),sello varchar(1000),firma_cliente varchar(2048),firma_server varchar(2048),confidencialidad boolean,usuario varchar(1000),PRIMARY KEY (id_registro))");
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
