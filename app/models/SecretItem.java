package models;

import play.db.ebean.Model;

import javax.persistence.*;

@Entity
public class SecretItem extends Model {

    public static Finder<Long, SecretItem> find;

    static {
        find = new Finder<Long, SecretItem>(
                Long.class, SecretItem.class
        );
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    public Long id;
    @Column(name = "title")
    public String title = "";
    /* This field is going to be overwritten using mass assignment attack */
    @Column(name = "is_admin")
    public boolean isAdmin = false;

    public Long getId() {
        return id;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public boolean getAdmin() {
        return isAdmin;
    }

    public void setAdmin(boolean status) {
        this.isAdmin = status;
    }

}
