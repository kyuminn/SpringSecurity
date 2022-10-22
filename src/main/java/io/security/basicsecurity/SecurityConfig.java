package io.security.basicsecurity;

// 2022 9월 기준 최신 버전 스프링부트 사용했을때 권장되는 스프링 시큐리티 설정 클래스

import lombok.RequiredArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationFailureHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import java.io.IOException;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
/**
 * to-do list : 인텔리제이 디버깅 , evalution tab 알아보기 , 토큰 기반 인증(jwt)? , jsessionid?=> 로그인 전에 페이지만 들어가도 생김 why? java-docs , 빌더 패턴 , 어댑터 패턴
 * 자세한 필터 설명은 강의자료에..
 *
 * Authentication : User, Authorities 를 가지는 인증객체
 * SecurityContext : Authentication 객체 저장소 class
 * SecurityContext 객체는 나중에 세션(HttpSession class)에 저장된다
 *
 * rememberMe 설정을 켜면 remember-me 라는 이름의 쿠키가 생성되고 , 이 쿠키 안에 인증정보가 담겨 있다
 * 개발자도구상에서 jsessionid를 일부러 삭제하고 재요청해도 다시 인증하지 않아도 된다.
 * rememberMe 쿠키가 없는 상황에서는 jsessionid 쿠키를 삭제했을때 인증페이지(로그인)으로 리다이렉트된다다
 * RememberMeAuthenticationFilter가 동작할 2가지 조건 1. Authentication 객체가 null 이면서(세션 만료) 2. 사용자가 요청 헤더에 remeber-me cookie 값을 가지고 있을 때
 * 다시 인증을 시도(token값과 User정보 조회)해서 인증객체를 가질 수 있도록 이 필터가 작동한다
 * 새로운 인증객체가 생성되면 다시 AuthenticationManager가 인증처리를 함
 *  chain.doFilter => FilterChain에 여러개의 필터가 등록되어 있고 한 필터를 거친 다음 필터로 가는 방식
 *
 *  SecurityContext 객체 안에 Authentication 객체가 없으면 AnonymousAuthenticationFilter 가 작동해서
 *  익명인증객체(Anonymous AuthenticationToken)을 생성한다, 익명인증객체는 세션에 저장되지 않는다. isAnonymous() = true인 경우
 *  로그인 페이지로 redirect 하는 로직.
 *
 *  인증방식  1. 스프링 시큐리티에서 세션을 생성해서 그 세션으로 인증하는 방식 2. 세션 대신 토큰으로 인증하는 방식 (jwt같이)
 **/

    private final UserDetailsService userDetailService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception{
        http
                .authorizeRequests()
                .anyRequest().authenticated(); // 어떤 요청이든지 인증을 받은 사용자만 자원에 접근할 수 있는 설정
        http
                .formLogin() //인증방식 : formLogin api
//                .loginPage("/loginPage")
//                .defaultSuccessUrl("/")
//                .failureUrl("/login")
//                .usernameParameter("userId")
//                .passwordParameter("passwd")
//                .loginProcessingUrl("/login_proc")
//                .successHandler(new AuthenticationSuccessHandler() {
//                    @Override
//                    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
//                        System.out.println("authentication:"+authentication.getName());
//                        response.sendRedirect("/");
//                    }
//                })
//                .failureHandler(new AuthenticationFailureHandler() {
//                    @Override
//                    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) throws IOException, ServletException {
//                        System.out.println("exception:"+exception.getMessage());
//                        response.sendRedirect("/login");
//                    }
//                })
//                .permitAll()
        ;
        http
                .logout() // default method : post
                .logoutUrl("/logout")
                .logoutSuccessUrl("/login")
                .addLogoutHandler(new LogoutHandler() {
                    @Override
                    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {
                        HttpSession session = request.getSession();
                        session.invalidate();
                    }
                })
                .logoutSuccessHandler(new LogoutSuccessHandler() {
                    @Override
                    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
                        response.sendRedirect("/login");
                    }
                })
                .deleteCookies("remember-me")
            .and()
                .rememberMe() // rememberMe 기능 활성화
                .rememberMeParameter("remember")
                .tokenValiditySeconds(3600) // 초 단위 , 1시간
                .userDetailsService(userDetailService);
        http
                .sessionManagement() // 동시 세션 제어 API
//                .sessionFixation().changeSessionId() //default가 changeSessionId, 인증할 때마다 세션 쿠키를 새로 발급(jsessionid가 변함)하여 공격자의 쿠키 조작을 방지
                .maximumSessions(1)
                .maxSessionsPreventsLogin(true) //true:기존 세션자가 인증을 우선으로 가진다 , false:가장 최근의 사용자가 인증권을 우선으로 가짐
//                .sessionCreationPolicy(SessionCreationPolicy.IF_REQUIRED)
        ;
        return http.build();
    }
}
