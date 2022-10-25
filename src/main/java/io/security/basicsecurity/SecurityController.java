package io.security.basicsecurity;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index(HttpSession httpSession){
        /**
            SecurityContext는 HttpSession 객체에서도 참조 가능.
         인증이 된 사용자가 인증 이후에 사이트에 접속을 할 때는 세션에 저장된 SecurityContext객체를 가지고 와서 그 객체를
         스레드로컬에 저장하는 방식으로 사용함.
         */
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        SecurityContext context =(SecurityContext) httpSession.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication1 = context.getAuthentication();
        /**
         * SecurityContext 객체를 두 가지 방식으로 참조 가능하다
         *  1. SecurityContextHolder 에서 꺼내오기
         *  2. HttpSession 에서 꺼내오기
         *  둘 다 같은 주소의 SecurityContext 객체를 참조한다
         */
        return "home";
    }

    @GetMapping("/thread")
    public String thread(){
        // 인증 후에 새로운 스레드를 형성했을 때 그 스레드는 기존 스레드의 인증 객체를 가지고 있지 않다 (공유 불가) : 기본 전략 (MODE_THREADLOCAL) 일 때 !
        new Thread(new Runnable() {
            @Override
            public void run() {
                Authentication authentication = SecurityContextHolder.getContext().getAuthentication(); // null
            }
        }).start();
        return "thread";
    }

//    @GetMapping("/loginPage")
//    public String loginPage(){
//        return "loginPage";
//    }
//
//    @GetMapping("/user")
//    public String user(){
//        return "user";
//    }
//
//    @GetMapping("/admin/pay")
//    public String adminPay(){
//        return "adminPay";
//    }
//
//    @GetMapping("/admin/**")
//    public String admin(){
//        return "admin";
//    }
//
//    @GetMapping("/denied")
//    public String denied(){
//        return "Access is denied";
//    }
//
//    @GetMapping("/login")
//    public String login(){
//        return "login";
//    }
//
//    @PostMapping("/")
//    public String postHome(){
//        return "postHome";
//    }
}
