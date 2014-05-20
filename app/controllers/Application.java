package controllers;

import models.Item;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.codecs.MySQLCodec;
import org.owasp.esapi.codecs.OracleCodec;
import play.data.DynamicForm;
import play.data.Form;
import play.db.DB;
import play.mvc.Controller;
import play.mvc.Result;
import views.html.main;

import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;

public class Application extends Controller {
    private static void emit_headers() {
        response().setHeader("X-XSS-Protection", "0");
        response().setHeader("Cache-Control", "must-revalidate,no-store,no-cache");
    }

    private static Result main(String reflect) {
        emit_headers();

        System.out.println("main reflect=" + reflect);

        return ok(main.render(Item.find.all(), Form.form(Item.class), reflect))   ;
    }

    public static Result index(){
        return main("");
    }

    public static Result reflect_esapi(){
        DynamicForm requestData = Form.form().bindFromRequest();
        String sanitized = ESAPI.encoder().encodeForHTML(requestData.get("whatever"));

        System.out.println("reflect_esapi sanitized=" + sanitized);

        if(sanitized == null) {
            return index();
        } else {
            return main(sanitized);
        }
    }

    public static Result reflect_raw(){
        DynamicForm requestData = Form.form().bindFromRequest();
        String myname = requestData.get("whatever");

        System.out.println("reflect_raw myname=" + myname);

        if(myname == null) {
            return index();
        } else {
            return main(myname);
        }
    }

    /*
    Use native Play object binding that should be immune to SQL injection.
    Vulns: SQLi, stored XSS
     */
    public static Result add_item_play() {

          Form<Item> itemForm = Form.form(Item.class);
          Item item = itemForm.bindFromRequest().get();
        System.out.println("add_item_play item=" + item);
          item.save();
        return redirect("/");
    }

    /*
    Insert data into SQL table using string concantendated query.
    Vulnerable to all kinds of SQL injection attacks.
     */
    private static Result raw_insert(String title) {
        Connection conn = DB.getConnection();

        if(conn == null) {
            return internalServerError("No database connection");
        }
        System.out.println("conn=" + conn);

        Statement statement = null;

        String query = "INSERT INTO item (title) VALUES ('" + title + "')";
        System.out.println("query=" + query);

        try {
            statement = conn.createStatement();
            statement.execute(query);
        } catch (SQLException e) {
            e.printStackTrace();
            return internalServerError(e.getMessage());
        } finally {
            try {
                if (statement != null)
                    statement.close();
                conn.close();
            } catch (SQLException e) {
                e.printStackTrace();
                return internalServerError(e.getMessage());
            }
        }

        return redirect("/");
    }

    /*
    Insert data using raw SQL insert with no escaping or validation.
    Vulns: SQLi, stored XSS
     */
    public static Result add_item_raw() {
        // create Item object only to extract the raw title field from it
        Form<Item> itemForm = Form.form(Item.class);
        Item item = itemForm.bindFromRequest().get();
        String title = item.getTitle();

        System.out.println("add_item_raw title=" + title);

        // insert the title to database
        return raw_insert(title);
    }

    public static Result add_item_esapi() {
        // create Item object only to extract the raw title field from it
        Form<Item> itemForm = Form.form(Item.class);
        Item item = itemForm.bindFromRequest().get();
        String title = item.getTitle();

        System.out.println("add_item_esapi title=" + title);

        String metadata = null;
        Connection conn = null;
        try {
            conn = DB.getConnection();
            metadata = conn.getMetaData().toString();
        } catch (SQLException e) {
            e.printStackTrace();
            return internalServerError(e.getMessage());
        } finally {
            if (conn != null)
                try {
                    conn.close();
                } catch (SQLException e) {
                    e.printStackTrace();
                    return internalServerError(e.getMessage());
                }
        }

        System.out.println("metadata=" + metadata + " sqlite=" + metadata.indexOf("sqlite") + " bad=" + metadata.indexOf("aaaa"));

        String sanitized;
        if (metadata.indexOf("sqlite") > 0) {
            // SQLite uses the same escaping as Oracle
            sanitized = ESAPI.encoder().encodeForSQL(new OracleCodec(), title);
        } else if (metadata.indexOf("mysql") > 0) {
            sanitized = ESAPI.encoder().encodeForSQL(new MySQLCodec(0), title);
        } else if (metadata.indexOf("oracle") > 0) {
            sanitized = ESAPI.encoder().encodeForSQL(new OracleCodec(), title);
        } else {
            return internalServerError("Unsupported database " + metadata);
        }

        System.out.println("sanitized=" + sanitized);

        // insert the title to database
        return raw_insert(sanitized);
    }

    public static Redirect redirect(String url) {

        System.out.println("redirect url=" + url);
        return new Redirect(302, url);
    }

}
