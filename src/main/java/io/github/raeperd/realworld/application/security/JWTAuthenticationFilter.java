package io.github.raeperd.realworld.application.security;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static java.util.Optional.ofNullable;
import static org.springframework.http.HttpHeaders.AUTHORIZATION;
import static org.springframework.security.core.context.SecurityContextHolder.getContext;

/**
 * JWT认证过滤器
 * 负责从HTTP请求头中提取JWT token并设置到Spring Security上下文中
 * 继承OncePerRequestFilter确保每个请求只执行一次过滤
 */
class JWTAuthenticationFilter extends OncePerRequestFilter {

    /**
     * 过滤器核心方法，处理每个HTTP请求
     * 从Authorization请求头中提取JWT token并设置认证信息
     * 
     * @param request HTTP请求对象
     * @param response HTTP响应对象
     * @param filterChain 过滤器链，用于继续处理请求
     */
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // 从请求头中获取Authorization字段
        ofNullable(request.getHeader(AUTHORIZATION))
                // 提取token部分，去掉"Token "前缀（RealWorld API规范使用"Token "而不是"Bearer "）
                .map(authHeader -> authHeader.substring("Token ".length()))
                // 创建JWT认证对象
                .map(JWT::new)
                // 如果token存在，则设置到Spring Security上下文中
                // jwt是无状态认证
                //- 不依赖服务器端session ：每个请求都是独立的
                // - token包含所有必要信息 ：用户ID、权限、过期时间等
                // - 必须每次验证 ：确保token未过期、未被篡改
                .ifPresent(getContext()::setAuthentication);
        
        // 继续执行过滤器链中的下一个过滤器
        filterChain.doFilter(request, response);
    }

    /**
     * JWT认证令牌类
     * 继承AbstractAuthenticationToken，用于在Spring Security中表示JWT认证信息
     * 这是一个简单的认证对象，实际的token验证由JWTAuthenticationProvider处理
     */
    @SuppressWarnings("java:S2160") // 忽略SonarQube关于equals方法的警告，这里不需要重写equals
    static class JWT extends AbstractAuthenticationToken {

        // JWT token字符串
        private final String token;

        /**
         * 构造JWT认证对象
         * 
         * @param token JWT token字符串
         */
        private JWT(String token) {
            super(null); // 不设置权限，权限将在认证成功后由AuthenticationProvider设置
            this.token = token;
        }

        /**
         * 获取认证主体（用户身份标识）
         * 在JWT认证中，token本身就是主体
         * 
         * @return JWT token字符串
         */
        @Override
        public Object getPrincipal() {
            return token;
        }

        /**
         * 获取认证凭据
         * JWT认证不需要额外的凭据信息
         * 
         * @return null
         */
        @Override
        public Object getCredentials() {
            return null;
        }
    }
}
