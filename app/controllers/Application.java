package controllers;

import models.Item;
import org.owasp.esapi.ESAPI;
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

    private static Result main(String reflect) {
        response().setHeader("X-XSS-Protection", "0");
        response().setHeader("Cache-Control","must-revalidate,no-store,no-cache");

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
            //return ok("<html><body>" + "Hello " + myname + "</body></html>").as("text/html; charset=utf-8");
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

    public static Result add_item_esapi() {
          Form<Item> itemForm = Form.form(Item.class);
          Item item = itemForm.bindFromRequest().get();
          System.out.println("add_item_esapi item=" + item);
          item.save();
        return redirect("/");
    }

    public static Result add_item_raw() {
        Form<Item> itemForm = Form.form(Item.class);
        Item item = itemForm.bindFromRequest().get();
        String title = item.getTitle();

        System.out.println("add_item_raw title=" + title);


        Connection conn = DB.getConnection();
        if(conn == null) {
            System.out.println("No connection");
            return internalServerError();
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
                statement.close();
                conn.close();
            } catch (SQLException e) {
                e.printStackTrace();

                return internalServerError(e.getMessage());
            }
        }


        return redirect("/");
    }

    public static Redirect redirect(String url) {

        System.out.println("redirect url=" + url);
        return new Redirect(302, url);
    }

}
