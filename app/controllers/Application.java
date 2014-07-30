package controllers;

import models.Item;
import models.SecretItem;
import org.apache.commons.codec.binary.Hex;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.codecs.MySQLCodec;
import org.owasp.esapi.codecs.OracleCodec;
import play.Logger;
import play.Play;
import play.data.DynamicForm;
import play.data.Form;
import play.db.DB;
import play.libs.Json;
import play.mvc.Controller;
import play.mvc.Result;
import views.html.main;
import views.html.poc;
import views.html.transactions;

import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.sql.Connection;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.Random;
import java.util.UUID;

public class Application extends Controller {
    /*
    Ensure our XSS is not blocked by the browser's built-in XSS filter.
    Obviously, on production websites you should do exactly the opposite
    @see <a href="http://ipsec.pl/http/2014/security-related-http-headers-wild.html">HTTP security headers</a>
    The second setHeader() disables caching, which makes tester's life
    a bit easier.
     */
    private static void emit_headers() {
        // disable browser XSS filter to make it more vulnerable
        // in production you definitely set this header to "1"
        response().setHeader("X-XSS-Protection", "0");
        // disable browser caching
        response().setHeader("Cache-Control", "must-revalidate,no-store,no-cache");
    }

    /*
    Render the main page with list of items and reflect parameter that may trigger
    XSS if it's not empty.
     */
    private static Result main(String reflect) {
        emit_headers();

        Logger.debug("main: reflect={}", reflect);

        return ok(main.render(Item.find.all(), SecretItem.find.all(), Form.form(SecretItem.class), Form.form(Item.class), reflect));
    }

    /*
    Display initial page with no XSS.
     */
    public static Result index(){
        return main("");
    }

    /*
     Display main page for the "transactional" part of the
     website.
     */
    public static Result transactions_index() {
        String sess = null;
        try {
            sess = request().cookies().get("session").value();
        } catch (Exception e) {
            sess = "(NONE)";
        }
        return ok(transactions.render(sess));
    }


    /*
    Generate CSRF token from session identifier using application.secret.
     */
    private static String xsrf_token(String session) {
        Mac mac = null;
        try {
            mac = Mac.getInstance("HmacSHA256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        byte[] secretByte = Play.application().configuration().getString("application.secret").getBytes();
        byte[] sessionByte = session.getBytes();
        SecretKey secret = new SecretKeySpec(secretByte, "HMACSHA256");

        assert mac != null;
        try {
            mac.init(secret);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }

        byte[] doFinal = mac.doFinal(sessionByte);
        return String.valueOf(Hex.encodeHex(doFinal));
    }

    /*
    Emulate log-in process - this just sets a random session
    cookie and related CSRF token. There is no real authentication,
    but it's not necessary here.
     */
    public static Result transactions_login() {
        response().discardCookie("error");
        String sess = UUID.randomUUID().toString();
        response().setCookie("session", sess);
        response().setCookie("XSRF-TOKEN", xsrf_token(sess));
        return redirect("/transactions/");
    }

    /*
    Delete any session related cookies.
     */
    public static Result transactions_logout() {
        response().discardCookie("session");
        response().discardCookie("secret");
        response().discardCookie("error");
        response().discardCookie("XSRF-TOKEN");
        return redirect("/transactions/");
    }

    /*
     Allow download of CSRF proof of concept HTML file. The file needs to be
     downloaded so that it doesn't run from the same origin as our application.
     */
    public static Result transactions_poc() {
        response().setHeader("Content-Disposition", "attachment; filename=\"poc.html\"");
        return ok(poc.render());
    }


    /*
    This API call returns a piece of sensitive data in response to a XMLHttpRequest
    call from the client. Authentication is required and this method implements
    an CSRF safeguard based on Cookie-to-Header technique supported by AngularJS.
    CORS is opened so that the first line of defence is opened.
     */
    public static Result transactions_secret() {
        String sess = null;
        String token = null;

        // open CORS
        response().setHeader("Access-Control-Allow-Origin", "null");
        response().setHeader("Access-Control-Allow-Credentials", "true");

        try {
            // check if user is authenticated
            sess = request().cookies().get("session").value();
        } catch (Exception e) {
            return ok(Json.newObject().put("data", "not authenticated"));
        }

        if (request().headers().containsKey("X-XSRF-TOKEN")) {
            // check if CSRF token was sent at all
            token = request().getHeader("X-XSRF-TOKEN");
        } else {
            return ok(Json.newObject().put("data", "missing XSRF token"));
        }

        // validate CSRF token and send response
        String valid_token = xsrf_token(sess);
        if (token.equals(valid_token)) {
            return ok(Json.newObject().put("data", "secret value"));
        } else {
            return ok(Json.newObject().put("data", "invalid CSRF token"));
        }

    }

    /*
    This API call returns a piece of sensitive data in response to a XMLHttpRequest
    call from the client. The user must be authenticated, but no CSRF controls are
    implemented in this insecure method. Additionally, CORS is opened so that
    XMLHttpRequest exploit can use POST method.

    @see <a href="http://cwe.mitre.org/data/definitions/352.html">CWE-352</a>
     */
    public static Result transactions_nosecret() {
        String sess = null;

        // open CORS
        response().setHeader("Access-Control-Allow-Origin", "null");
        response().setHeader("Access-Control-Allow-Credentials", "true");

        try {
            // check if user is authenticated
            sess = request().cookies().get("session").value();
        } catch (Exception e) {
            return ok(Json.newObject().put("data", "not authenticated"));
        }

        // send response
        return ok(Json.newObject().put("data", "secret value"));


    }

    /*
    Extract a string parameter from GET request and pass to the template
    where it will be reflected with no sanitisation. Vulnerable to reflected
    XSS.

    @see <a href="http://cwe.mitre.org/data/definitions/79.html">CWE-79</a>
     */
    public static Result reflect_raw() {
        DynamicForm requestData = Form.form().bindFromRequest();
        String myname = requestData.get("whatever");

        Logger.debug("reflect_raw: myname={}", myname);

        if (myname == null) {
            return index();
        } else {
            return main(myname);
        }
    }

    /*
    Extract a string parameter from GET request and pass to the template, but
    first sanitise using OWASP ESAPI encoder. Not vulnerable to XSS.
     */
    public static Result reflect_esapi(){
        DynamicForm requestData = Form.form().bindFromRequest();
        String sanitized = ESAPI.encoder().encodeForHTML(requestData.get("whatever"));

        Logger.debug("reflect_esapi: sanitized={}", sanitized);

        if(sanitized == null) {
            return index();
        } else {
            return main(sanitized);
        }
    }

    /*
   Create an SecretItem object with native Play binding that is
   not vulnerable to SQL injection, but is vulnerable to mass
   assignment. It's *not* vulnerable to XSS because the respective
   template that displays this object is protected by native Play
   escaping (by not using the @Html() method).

   @see <a href="http://cwe.mitre.org/data/definitions/915.html">CWE-915</a>
    */
    public static Result add_secretitem_dumb() {

        Form<SecretItem> itemForm = Form.form(SecretItem.class);
        SecretItem item = itemForm.bindFromRequest().get();

        Logger.debug("add_secretitem_play: secretitem={}", item);

        item.save();
        return redirect("/");
    }

    /*
    Protected version of the {@link #add_secretitem_dumb() add_secretitem_dumb}
    method that explicitly lists model fields that are allowed during the binding.
    In this case it's just one field - title.
     */
    public static Result add_secretitem_protected() {

        Form<SecretItem> itemForm = Form.form(SecretItem.class);
        SecretItem item = itemForm.bindFromRequest("title").get();

        Logger.debug("add_secretitem_play: secretitem={}", item);

        item.save();
        return redirect("/");
    }

    /*
    Insert data into SQL table using query contatenated from string parts,
    including unsanitised user input. Vulnerable to all kinds of SQL injection
    attacks. Not used directly, called by other methods here.

    @see <a href="http://cwe.mitre.org/data/definitions/89.html">CWE-89</a>
     */
    private static Result raw_insert(String title) {
        Connection conn = DB.getConnection();
        Logger.debug("raw_insert: conn={}", conn);


        if(conn == null) {
            return internalServerError("No database connection");
        }

        Statement statement = null;

        // avoid stupid existing id lookups
        Random rand = new Random();
        String query = "INSERT INTO item (id, title) VALUES ('" + rand.nextLong() + "','" + title + "')";
        Logger.debug("raw_insert: query={}", query);

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
    Vulnerable to SQLi and stored XSS.

    @see <a href="http://cwe.mitre.org/data/definitions/89.html">CWE-89</a>
    @see <a href="http://cwe.mitre.org/data/definitions/79.html">CWE-79</a>
     */
    public static Result add_item_raw() {
        // create Item object only to extract the raw title field from it
        Form<Item> itemForm = Form.form(Item.class);
        Item item = itemForm.bindFromRequest().get();
        String title = item.getTitle();

        Logger.debug("add_item_raw: title={}", title);

        // insert the title to database
        return raw_insert(title);
    }

    /*
    Insert data using raw SQL insert but pass through ESAPI encoder first.
    Not vulnerable to SQLi, but still vulnerable to stored XSS.

    @see <a href="http://cwe.mitre.org/data/definitions/79.html">CWE-79</a>
     */
    public static Result add_item_esapi() {
        // create Item object only to extract the raw title field from it
        Form<Item> itemForm = Form.form(Item.class);
        Item item = itemForm.bindFromRequest().get();
        String title = item.getTitle();

        Logger.debug("add_item_esapi: title={}", title);

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

        String sanitized;

        Logger.debug("add_item_esapi: SQL engine={}", metadata);

        if (metadata.indexOf("sqlite") > 0) {
            // SQLite uses the same escaping scheme as Oracle
            sanitized = ESAPI.encoder().encodeForSQL(new OracleCodec(), title);
        } else if (metadata.indexOf("mysql") > 0) {
            sanitized = ESAPI.encoder().encodeForSQL(new MySQLCodec(0), title);
        } else if (metadata.indexOf("Oracle") > 0) {
            sanitized = ESAPI.encoder().encodeForSQL(new OracleCodec(), title);
        } else if (metadata.indexOf("h2") > 0) {
            sanitized = ESAPI.encoder().encodeForSQL(new OracleCodec(), title);
        } else {
            return internalServerError("Unsupported database " + metadata);
        }

        Logger.debug("add_item_esapi: sanitized={}", sanitized);

        // insert the title to database
        return raw_insert(sanitized);
    }

    /*
    Create Item object using native Play binding that is not
    vulnerable to SQL injection. It is still vulnerable to
    mass assignment, but it doesn't really matter with Item objects.
     */
    public static Result add_item_play() {

        Form<Item> itemForm = Form.form(Item.class);
        Item item = itemForm.bindFromRequest().get();

        Logger.debug("add_item_play: item={}", item);

        item.save();
        return redirect("/");
    }

    /*
    Return a HTTP redirect. Used internally only.
     */
    public static Redirect redirect(String url) {

        Logger.debug("redirect: url={}", url);
        return new Redirect(302, url);
    }

    /*
    Wrapper that can be used in routes. Delivers an exquisite open redirect vulnerability.

    @see <a href="http://cwe.mitre.org/data/definitions/601.html">CWE-601</a>
     */
    public static Result get_redirect(String url) {
        Logger.debug("get_redirect: url={}", url);
        return redirect(url);
    }

}
