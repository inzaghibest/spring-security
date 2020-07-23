package com.zhangxp;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.security.crypto.bcrypt.BCrypt;
import org.springframework.test.context.junit4.SpringRunner;

@RunWith(SpringRunner.class)
public class TestBCypt {
    @Test
    public void test()
    {
        // 对密码进行加密
        String strpw = BCrypt.hashpw("123", BCrypt.gensalt());
        System.out.println("-----------------" + strpw + "---------------");

        // 校验密码
        Boolean bChecked = BCrypt.checkpw("123",
                "$2a$10$R.kUP2WSdzWQL3qzo6pF/uzpqPsvp/q1HF0fm9KZR/O8KwJgHe5Fm");
        System.out.println("校验结果:" + bChecked);

    }
}
