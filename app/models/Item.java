package models;

import play.db.ebean.Model;

import javax.persistence.*;

@Entity
public class Item extends Model {

    public static Finder<Long, Item> find;

    static {
        find = new Finder<Long, Item>(
                Long.class, Item.class
        );
    }
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "id", nullable = false)
    public Long id;
    @Column(name = "title")
    public String title = "";

    public String getTitle() {
        return title;
    }

    public Long getId() {
        return id;
    }

}


