package cn.haitaoss.config;

import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * @author haitao.chen
 * email haitaoss@aliyun.com
 * date 2023-05-18 17:21
 *
 */
@RestController
public class IndexController {
	@RequestMapping("index")
	public Object index() {
		return "ok...";
	}
}
