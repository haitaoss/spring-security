package cn.haitaoss.config;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

public  interface A {
		@GetMapping("/index2")
		@ResponseBody
		public Object index2(@RequestParam("xx") Object obj);
	}
