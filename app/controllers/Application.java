package controllers;

import org.owasp.esapi.ESAPI;
import play.data.DynamicForm;
import play.data.Form;
import play.mvc.Controller;
import play.mvc.Result;
import views.html.main;

public class Application extends Controller {

    public static Result index(){
        DynamicForm requestData = Form.form().bindFromRequest();
        String myname = ESAPI.encoder().encodeForHTML(requestData.get("whatever"));
        if(myname == null) {
            return ok(main.render()) ;
        } else {
            return ok("<html><body>" + "Hello " + myname + "</body></html>").as("text/html; charset=utf-8");
        }
    }

    public static Result index2(){
        DynamicForm requestData = Form.form().bindFromRequest();
        String myname = requestData.get("whatever");
        if(myname == null) {
            return ok(main.render()) ;
        } else {
            return ok("<html><body>" + "Hello " + myname + "</body></html>").as("text/html; charset=utf-8");
        }
    }

}
