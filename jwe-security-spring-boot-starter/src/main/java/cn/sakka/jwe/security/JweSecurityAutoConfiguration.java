package cn.sakka.jwe.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * @author sakka
 * @version 1.0
 * @description: jwe security 自动配置类
 * @date 2023/4/5
 */
@ConditionalOnProperty(value = "jwe.security.enabled", havingValue = "true")
@Configuration
public class JweSecurityAutoConfiguration {


    @Bean
    public JweSecurityMappingJackson2HttpMessageConverter jweMappingJackson2HttpMessageConverter(@Autowired JweSecurityProperties jweSecurityProperties) {
        return new JweSecurityMappingJackson2HttpMessageConverter(jweSecurityProperties);
    }

    @ConfigurationProperties(prefix = "jwe.security")
    @Bean
    public JweSecurityProperties jweSecurityProperties() {
        return new JweSecurityProperties();
    }

}
