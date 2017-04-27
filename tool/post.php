<?php
//过滤提交post，防止sql注入和xss跨站攻击
	public function clean_post($post)
	{		
		if(!get_magic_quotes_gpc())
		{
			if(is_array($post)){
            foreach($post as $n=>$v){
				$post[$n] = mysql_real_escape_string($v);
                $post[$n] = addslashes($v);
				$post[$n] = str_replace("_", "/_", $v);
				$post[$n] = str_replace("%", "/%", $v);
				$post[$n] = nl2br($v);
				$post[$n] = htmlspecialchars($v);
            }				
			}else{
				$post = mysql_real_escape_string($post);
				$post = addslashes($post);
				$post = str_replace("_", "/_", $post);
				$post = str_replace("%", "/%", $post);
				$post = nl2br($post);
				$post = htmlspecialchars($post);
			} 
		}		
		return $post;
	}
?>