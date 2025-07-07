package io.github.raeperd.realworld.application.security;

import io.github.raeperd.realworld.domain.jwt.JWTDeserializer;
import io.github.raeperd.realworld.domain.jwt.JWTPayload;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import static java.util.Collections.singleton;
import static java.util.Optional.of;

/**
 * JWT认证提供者
 * 实现Spring Security的AuthenticationProvider接口
 * 负责验证JWT token的有效性并创建认证成功的Authentication对象
 */
class JWTAuthenticationProvider implements AuthenticationProvider {

    // JWT反序列化器，用于解析和验证JWT token
    private final JWTDeserializer jwtDeserializer;

    /**
     * 构造JWT认证提供者
     * 
     * @param jwtDeserializer JWT反序列化器，用于解析JWT token
     */
    JWTAuthenticationProvider(JWTDeserializer jwtDeserializer) {
        this.jwtDeserializer = jwtDeserializer;
    }

    /**
     * 认证方法，验证JWT token并创建认证成功的Authentication对象
     * 这是Spring Security认证流程的核心方法
     * 
     * @param authentication 待认证的Authentication对象（来自JWTAuthenticationFilter）
     * @return 认证成功的JWTAuthentication对象，包含用户信息和权限
     * @throws AuthenticationException 认证失败时抛出异常
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return of(authentication)
                // 将Authentication对象转换为JWT类型
                .map(JWTAuthenticationFilter.JWT.class::cast)
                // 获取JWT token字符串
                .map(JWTAuthenticationFilter.JWT::getPrincipal)
                .map(Object::toString)
                // 使用JWTDeserializer解析token，获取用户信息，并创建认证成功的对象
                .map(token -> new JWTAuthentication(token, jwtDeserializer.jwtPayloadFromJWT(token)))
                // 如果任何步骤失败，抛出IllegalStateException
                .orElseThrow(IllegalStateException::new);
    }

    /**
     * 判断此认证提供者是否支持指定类型的Authentication
     * Spring Security会调用此方法来确定是否使用此Provider进行认证
     * 
     * @param authentication 待检查的Authentication类型
     * @return 如果支持JWT类型的认证则返回true，否则返回false
     */
    @Override
    public boolean supports(Class<?> authentication) {
        // 只支持JWTAuthenticationFilter.JWT类型的认证
        return JWTAuthenticationFilter.JWT.class.isAssignableFrom(authentication);
    }

    /**
     * JWT认证成功后的Authentication实现
     * 包含已验证的用户信息和权限
     * 这个对象会被存储在Spring Security上下文中，供后续的授权决策使用
     */
    @SuppressWarnings("java:S2160") // 忽略SonarQube关于equals方法的警告
    private static class JWTAuthentication extends AbstractAuthenticationToken {

        // JWT载荷信息，包含用户ID等关键信息
        private final JWTPayload jwtPayload;
        // 原始JWT token字符串
        private final String token;

        /**
         * 构造认证成功的JWT Authentication对象
         * 
         * @param token JWT token字符串
         * @param jwtPayload 解析后的JWT载荷信息
         */
        private JWTAuthentication(String token, JWTPayload jwtPayload) {
            // 设置用户权限为"USER"（在实际项目中可能需要从数据库获取具体权限）
            super(singleton(new SimpleGrantedAuthority("USER")));
            // 标记为已认证状态
            super.setAuthenticated(true);
            this.jwtPayload = jwtPayload;
            this.token = token;
        }

        /**
         * 获取认证主体（用户信息）
         * 返回JWT载荷，包含用户ID等信息
         * 
         * @return JWT载荷对象
         */
        @Override
        public Object getPrincipal() {
            return jwtPayload;
        }

        /**
         * 获取认证凭据
         * 返回原始的JWT token字符串
         * 
         * @return JWT token字符串
         */
        @Override
        public Object getCredentials() {
            return token;
        }
    }

}
