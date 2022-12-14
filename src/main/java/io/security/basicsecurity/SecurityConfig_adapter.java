package io.security.basicsecurity;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.AuthenticationEntryPointFailureHandler;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
/**
 *  낮은 버전의 스프링 부트, 스프링 시큐리티에서 사용하는 방식 (현재는 권장x)
 *  스프링 시큐리티가 초기화될때 WebSecurityConfigurerAdapter를 호출하고, configure() 도 호출된다
 *  이 configure method를 오버라이딩해서 시큐리티 설정을 나의 프로젝트에 맞게 customize 할 수 있다
 *  시큐리티, 설정 부분은 주석처리함, 낮은버전에서 사용할 때는 어노테이션 주석 풀고 , 상속받는 클래스 deprecated 안되어있는지 확인하고 쓸 것
 *  이 버전에서 다중 config를 하려면 WebSecurityConfigureAdapter를 상속받는 default class를 하나 더 만들고 @EnableWebSecurity 와 @Order를 추가해주면 된다.
 *
 */


//@Configuration
//@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig_adapter extends WebSecurityConfigurerAdapter {

    // 이 방식에서는 UserDetailService를 직접 bean으로 등록하나봄 ..?
    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http
                .authorizeRequests()
                .anyRequest().authenticated();
        http
                .formLogin()
                .loginPage("/loginPage")
                .defaultSuccessUrl("/")
                .failureUrl("/login")
                .usernameParameter("userId")
                .passwordParameter("passwd")
                .loginProcessingUrl("/login_proc")
                .successHandler(new AuthenticationSuccessHandler() {
                    @Override
                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        System.out.println("authentication:"+authentication.getName());
                        response.sendRedirect("/");
                    }
                })
                .failureHandler(new AuthenticationFailureHandler() {
                    @Override
                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
                        System.out.println("exception:"+exception.getMessage());
                        response.sendRedirect("/login");
                    }
                })
                .permitAll()
        ;
    }
    // In-memory user 생성
    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.inMemoryAuthentication().withUser("user").password("{noop}1111").roles("USER");
        auth.inMemoryAuthentication().withUser("sys").password("{noop}1111").roles("SYS");
        auth.inMemoryAuthentication().withUser("admin").password("{noop}1111").roles("ADMIN");

    }
}
