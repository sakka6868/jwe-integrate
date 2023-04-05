package cn.sakka.jwe.security;

import java.lang.annotation.Retention;
import java.lang.annotation.Target;

import static java.lang.annotation.ElementType.TYPE;
import static java.lang.annotation.RetentionPolicy.RUNTIME;

/**
 * @author sakka
 * @version 1.0
 * @description: //TODO
 * @date 2023/3/30
 */
@Target({TYPE})
@Retention(RUNTIME)
public @interface JweSecurityEntity {
}
