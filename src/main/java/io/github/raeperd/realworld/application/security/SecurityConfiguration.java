package io.github.raeperd.realworld.application.security;

import io.github.raeperd.realworld.domain.jwt.JWTDeserializer;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.ConstructorBinding;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.builders.WebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;

import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.POST;

/**
 * Spring Security 安全配置类
 * 配置JWT认证、CORS跨域、权限控制等安全策略
 * 适用于前后端分离的REST API架构
 */
@EnableConfigurationProperties(SecurityConfigurationProperties.class)
@Configuration
public class SecurityConfiguration extends WebSecurityConfigurerAdapter implements WebMvcConfigurer {

    private final SecurityConfigurationProperties properties;

    SecurityConfiguration(SecurityConfigurationProperties properties) {
        this.properties = properties;
    }

    /**
     * 配置Web安全忽略规则
     * 完全跳过Spring Security过滤器链的端点
     */
    @Override
    public void configure(WebSecurity web) {
        // 用户注册和登录接口不需要经过Security过滤器
        web.ignoring().antMatchers(POST, "/users", "/users/login");
    }

    /**
     * 配置HTTP安全策略
     * 设置JWT认证、CORS、权限控制等核心安全配置
     */
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        // 禁用CSRF保护，REST API使用JWT token进行身份验证，不需要CSRF保护
        http.csrf().disable();
        
        // 启用CORS跨域资源共享，允许前端应用从不同域名访问API
        http.cors();
        
        // 禁用表单登录，不使用传统的用户名/密码表单登录方式
        http.formLogin().disable();
        
        // 禁用默认登出功能，JWT是无状态的，不需要服务器端登出处理
        http.logout().disable();
        
        // 在用户名密码认证过滤器之前添加JWT认证过滤器，优先处理JWT token验证
        http.addFilterBefore(new JWTAuthenticationFilter(), UsernamePasswordAuthenticationFilter.class);
        
        // 配置请求授权规则
        http.authorizeRequests()
                // 允许所有人访问用户档案（GET请求）
                .antMatchers(GET, "/profiles/*").permitAll()
                // 允许所有人读取文章内容
                .antMatchers(GET, "/articles/**").permitAll()
                // 允许所有人访问标签列表
                .antMatchers(GET, "/tags/**").permitAll()
                // 其他所有请求都需要身份验证
                .anyRequest().authenticated();
    }

    /**
     * 配置JWT认证提供者
     * 负责验证和处理JWT token
     */
    @Bean
    JWTAuthenticationProvider jwtAuthenticationProvider(JWTDeserializer jwtDeserializer) {
        return new JWTAuthenticationProvider(jwtDeserializer);
    }

    /**
     * 配置密码编码器
     * 使用BCrypt算法对密码进行加密存储
     */
    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    /**
     * 配置CORS跨域映射
     * 允许前端应用跨域访问API
     */
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**") // 对所有路径生效
                // 允许的HTTP方法
                .allowedMethods("GET", "HEAD", "POST", "DELETE", "PUT")
                // 允许的源域名，从配置文件中读取
                .allowedOrigins(properties.getAllowedOrigins().toArray(new String[0]))
                // 允许所有请求头
                .allowedHeaders("*")
                // 允许发送Cookie和认证信息
                .allowCredentials(true);
    }
}

/**
 * 安全配置属性类
 * 从application.yml中读取security配置项
 */
@ConstructorBinding
@ConfigurationProperties("security")
class SecurityConfigurationProperties {
    // CORS允许的源域名列表
    private final List<String> allowedOrigins;

    SecurityConfigurationProperties(List<String> allowedOrigins) {
        this.allowedOrigins = allowedOrigins;
    }

    /**
     * 获取CORS允许的源域名列表
     */
    public List<String> getAllowedOrigins() {
        return allowedOrigins;
    }
}