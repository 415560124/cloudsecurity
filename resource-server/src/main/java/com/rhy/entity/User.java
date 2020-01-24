package com.rhy.entity;


import org.springframework.stereotype.Component;

import java.io.Serializable;

/**
 * @Auther: Herion_Rhy
 * @Description:
 * @Date: Created in 2019/12/28 16:57
 * @Modified By:
 * @Version: 1.0.0
 */
@Component
public class User implements Serializable {
    private static final long serialVersionUID = 1L;
    private long id;
    private String userName;
    private String pwd;
    private String available;
    private String note;

    public long getId() {
        return id;
    }

    public void setId(long id) {
        this.id = id;
    }

    public String getUserName() {
        return userName;
    }

    public void setUserName(String userName) {
        this.userName = userName;
    }

    public String getPwd() {
        return pwd;
    }

    public void setPwd(String pwd) {
        this.pwd = pwd;
    }

    public String getAvailable() {
        return available;
    }

    public void setAvailable(String available) {
        this.available = available;
    }

    public String getNote() {
        return note;
    }

    public void setNote(String note) {
        this.note = note;
    }

    @Override
    public String toString() {
        return "User{" +
                "id=" + id +
                ", userName='" + userName + '\'' +
                ", pwd='" + pwd + '\'' +
                ", available='" + available + '\'' +
                ", note='" + note + '\'' +
                '}';
    }
}
