<?php
/**
 * 常用工具
 * @author 冯兴柱
 * @version v1.1
 * 
 * Objec转换数组函数： object_array($array)
 * curl获取json内容 ：curl_file_get_contents($durl)
 * 直接获取json中的数据，并且转换为数组并且返回： get_json($url)
 */
namespace widget;
class Tools
{
	//构造函数
	public function __construct()
	{
		
	}
	/**
	 * Object 转换 数组
	 * 常用于获取json是object类型。
	 * @return array $array
	 */
	public function object_array($array) {
		if(is_object($array)) {
			$array = (array)$array;
		} if(is_array($array)) {
			foreach($array as $key=>$value) {
				$array[$key] = $this->object_array($value);
			}
		}
		return $array;
	}
	/**
	 * 	curl get获取url中的内容
	 * @param string $durl
	 * @param string $r
	 */
	public function curl_file_get_contents($durl){
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_URL, $durl);
		curl_setopt($ch, CURLOPT_TIMEOUT, 5);
		curl_setopt($ch, CURLOPT_USERAGENT, _USERAGENT_);
		curl_setopt($ch, CURLOPT_REFERER,_REFERER_);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
		$r = curl_exec($ch);
		curl_close($ch);
		return $r;
	}
	/**
	 *  json 直接获取
	 *  第一步：$this->curl_file_get_contents($durl)  
	 *  第二步：json_decode 转换
	 *  第三步：$thi->object_array($array)
	 *  @param string $url
	 *  @return array $temp
	 */
	public function get_json($url)
	{
		//通过url获取接口中的json
		$temp=$this->curl_file_get_contents($url);
		//把获取json转换为php的字符串变量
		$temp=json_decode($temp);
		//把字符串转换为数组
		$temp=$this->object_array($temp);
		//返回数组
		return $temp;
		
	}
	/**
	 * XSS过滤 （跨站脚本）
	 * @param string $val
	 * @return string $val
	 */
	public function RemoveXSS($val) {
		// remove all non-printable characters. CR(0a) and LF(0b) and TAB(9) are allowed
		// this prevents some character re-spacing such as <java\0script>
		// note that you have to handle splits with \n, \r, and \t later since they *are* allowed in some inputs
		$val = preg_replace('/([\x00-\x08,\x0b-\x0c,\x0e-\x19])/', '', $val);
	
		// straight replacements, the user should never need these since they're normal characters
		// this prevents like <IMG SRC=@avascript:alert('XSS')>
		$search = 'abcdefghijklmnopqrstuvwxyz';
	   	$search .= 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
	 	  $search .= '1234567890!@#$%^&*()';
	  	$search .= '~`";:?+/={}[]-_|\'\\';
	   	for ($i = 0; $i < strlen($search); $i++) {
		   // ;? matches the ;, which is optional
				// 0{0,7} matches any padded zeros, which are optional and go up to 8 chars
				 
				// @ @ search for the hex values
				$val = preg_replace('/(&#[xX]0{0,8}'.dechex(ord($search[$i])).';?)/i', $search[$i], $val); // with a ;
						// @ @ 0{0,7} matches '0' zero to seven times
						$val = preg_replace('/(&#0{0,8}'.ord($search[$i]).';?)/', $search[$i], $val); // with a ;
			}
   
		// now the only remaining whitespace attacks are \t, \n, and \r
		$ra1 = Array('javascript', 'vbscript', 'expression', 'applet', 'meta', 'xml', 'blink', 'link', 'style', 'script', 'embed', 'object', 'iframe', 'frame', 'frameset', 'ilayer', 'layer', 'bgsound', 'title', 'base');
				$ra2 = Array('onabort', 'onactivate', 'onafterprint', 'onafterupdate', 'onbeforeactivate', 'onbeforecopy', 'onbeforecut', 'onbeforedeactivate', 'onbeforeeditfocus', 'onbeforepaste', 'onbeforeprint', 'onbeforeunload', 'onbeforeupdate', 'onblur', 'onbounce', 'oncellchange', 'onchange', 'onclick', 'oncontextmenu', 'oncontrolselect', 'oncopy', 'oncut', 'ondataavailable', 'ondatasetchanged', 'ondatasetcomplete', 'ondblclick', 'ondeactivate', 'ondrag', 'ondragend', 'ondragenter', 'ondragleave', 'ondragover', 'ondragstart', 'ondrop', 'onerror', 'onerrorupdate', 'onfilterchange', 'onfinish', 'onfocus', 'onfocusin', 'onfocusout', 'onhelp', 'onkeydown', 'onkeypress', 'onkeyup', 'onlayoutcomplete', 'onload', 'onlosecapture', 'onmousedown', 'onmouseenter', 'onmouseleave', 'onmousemove', 'onmouseout', 'onmouseover', 'onmouseup', 'onmousewheel', 'onmove', 'onmoveend', 'onmovestart', 'onpaste', 'onpropertychange', 'onreadystatechange', 'onreset', 'onresize', 'onresizeend', 'onresizestart', 'onrowenter', 'onrowexit', 'onrowsdelete', 'onrowsinserted', 'onscroll', 'onselect', 'onselectionchange', 'onselectstart', 'onstart', 'onstop', 'onsubmit', 'onunload');
						$ra = array_merge($ra1, $ra2);
						 
								$found = true; // keep replacing as long as the previous round replaced something
								while ($found == true) {
								$val_before = $val;
								for ($i = 0; $i < sizeof($ra); $i++) {
								$pattern = '/';
								for ($j = 0; $j < strlen($ra[$i]); $j++) {
								if ($j > 0) {
								$pattern .= '(';
									$pattern .= '(&#[xX]0{0,8}([9ab]);)';
											$pattern .= '|';
											$pattern .= '|(&#0{0,8}([9|10|13]);)';
											$pattern .= ')*';
									}
									$pattern .= $ra[$i][$j];
									}
									$pattern .= '/i';
									$replacement = substr($ra[$i], 0, 2).'<x>'.substr($ra[$i], 2); // add in <> to nerf the tag
									$val = preg_replace($pattern, $replacement, $val); // filter out the hex tags
									if ($val_before == $val) {
									// no replacements were made, so exit the loop
									$found = false;
								}
								}
		}
		return $val;
		}
		/**
		 * sql 脚本注入过滤
		 * @param string $str
		 * @return string $str
		 */
		function replace_sql($str)
		{
			$str = str_ireplace(" and ","",$str);
			$str = str_ireplace("execute","",$str);
			$str = str_ireplace("update","",$str);
			$str = str_ireplace("count","",$str);
			$str = str_ireplace("chr","",$str);
			$str = str_ireplace("mid","",$str);
			$str = str_ireplace("master","",$str);
			$str = str_ireplace("truncate","",$str);
			$str = str_ireplace("char","",$str);
			$str = str_ireplace("declare","",$str);
			$str = str_ireplace("select","",$str);
			$str = str_ireplace("create","",$str);
			$str = str_ireplace("delete","",$str);
			$str = str_ireplace("insert","",$str);
			$str = str_ireplace("\'","",$str);
			//$str = str_ireplace("\"","",$str);
			$str = str_ireplace("\\","",$str);
			$str = str_ireplace(" ","",$str);
			$str = str_ireplace(" or ","",$str);
			$str = str_ireplace("=","",$str);
			$str = str_ireplace("0x","0 x",$str);
			$str = str_ireplace(";","",$str);
			$str = str_ireplace("--","",$str);
			//echo $str;
			return $str;
		}
}