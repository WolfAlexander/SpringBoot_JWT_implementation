package me.learning.entity;

import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import lombok.ToString;

import javax.persistence.*;

@Entity
@Table(name = "Role")
@Getter
@Setter
@NoArgsConstructor
@ToString
public class RoleEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long id;

    private String name;

    public RoleEntity(String name) {
        this.name = name;
    }
}
