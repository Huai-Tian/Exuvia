//! JNI 符号名机械推导——JNI 规范的格式事实，零语义。
//! native stub 的 Java 侧（FQCN + 方法名 + 描述符）→ so 导出表中的符号名。
//!
//! 两条推导路径（按 JNI 规范）：
//! ① 短名（非重载）：`Java_<类名 . → _>_<方法名>`
//! ② mangled 签名（重载）：`Java_<类名>_<方法名>__<参数逐字符转义>`
//!    `/`→`_`、`;`→`_2`、`[`→`_3`、`_`→`_1`；其余字符原样。
//!    完整规范的扩展转义（$、内部类等）留 TODO，第一代壳语料不涉及。

/// 短名：`com.example.Foo` + `bar` → `Java_com_example_Foo_bar`
pub fn short_name(class_fqcn: &str, method: &str) -> String {
    format!("Java_{}_{}", class_fqcn.replace('.', "_"), method)
}

/// mangled 签名（重载场景）：参数列表逐字符转义（不含返回类型）。
/// `com.example.Foo` + `bar` + `(Ljava/lang/String;[B)V` → `Java_com_example_Foo_bar__Ljava_lang_String_2_3B`
pub fn mangled_name(class_fqcn: &str, method: &str, descriptor: &str) -> String {
    let args = descriptor
        .strip_prefix('(')
        .and_then(|rest| rest.split(')').next())
        .unwrap_or("");
    let mut sig = String::new();
    for ch in args.chars() {
        match ch {
            '/' => sig.push('_'),
            ';' => sig.push_str("_2"),
            '[' => sig.push_str("_3"),
            '_' => sig.push_str("_1"),
            _ => sig.push(ch),
        }
    }
    format!("Java_{}_{}__{}", class_fqcn.replace('.', "_"), method, sig)
}

/// 定位候选（按 JNI 规范优先级）：先短名，未命中再 mangled。
pub fn candidates(class_fqcn: &str, method: &str, descriptor: &str) -> [String; 2] {
    [short_name(class_fqcn, method), mangled_name(class_fqcn, method, descriptor)]
}
