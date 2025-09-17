## Nginx HTTP WAF v2.1（草案）：JSON 继承与合并语义（扩展版）

注意：本文件为 v2.1 扩展草案。当前 v2.0 首版采用“简化合并语义”，详见 `waf-json-spec-v2.0-simplified.md`。当实现与控制台具备更强可视化能力后，再回归本扩展版设计。

本文档定义 v2.1 规则 JSON 的“继承（extends）与合并（merge）”扩展语义，作为后续演进的参考。若实现出现偏差，应先更新本文档，再开展修改。

### 1. 适用范围与对象

- 适用对象：`WAF_RULES_JSON/*.json` 规则工件，M1 阶段的“数据面解析与合并”。
- 关键参考：`docs/refactor-plan-v2.md`、`docs/milestones.md`（M1 范围与步骤）。

### 2. 术语约定

- 入口 JSON：Nginx 指令 `waf_rules_json` 指向的文件（例如 D）。
- 父/基文件：被入口或上层 via `meta.extends` 引用的文件（例如 C/B/A）。
- 被引入集合 imported_set：对“本层 `meta.extends` 指向的每个父文件”分别求得其最终结果后（见下文“层级递归”），按“左→右”顺序拼接得到的集合。
- 本地集合 local_set：当前文件 `rules` 字段中的规则集合（数组顺序即为规则顺序）。
- 额外集合 extra_set：当前文件 `extraRules` 字段中的规则集合（数组顺序即为规则顺序）。
- 合并结果 result：本层完成“过滤/禁用/追加/去重”后的平面化规则集合；作为下一层的父集输入。

### 3. 顶层字段与总体原则

- `meta`：元信息与合并策略控制，包含 `extends/includeTags/excludeTags/duplicatePolicy` 等。
  - 重要：`meta` 不参与跨层“字段值合并”，亦不被子层“继承转存”。其作用仅限于“当前层的合并过程控制”。最终产物的 `meta` 取自入口 JSON（便于标识 name/versionId 等），父层 `meta` 不向下传递。
- `rules`：当前文件自有规则。
- `disableById/disableByTag`：当前层对“本层合并中间结果”的过滤（移除），不向后形成“禁用记忆”。
- `extraRules`：在禁用之后的追加集合。
- `policies`：与运行期策略相关的配置（M1 仅透传，编译期/M2 再处理）。
- `duplicatePolicy`：本层“去重策略”，默认值为 `warn_skip`。

秩序优先原则：所有合并与去重按照“可见顺序（extends 左→右；其后本地 rules；其后 extraRules）”执行，保证结果可预测、可解释。

### 4. 层级递归与循环/深度控制

对任一文件 X：
1) 解析 JSON（启用注释/尾逗号容错）。
2) 递归解析 `meta.extends[]`，对每个父文件 Y：
   - 若检测到环（访问中节点再次被访问），报错“循环继承”。
   - 深度上限：由指令 `waf_json_extends_max_depth` 控制；0 表示不限深度但仍进行环检测；超过上限报错。
3) 对每个父文件求其“最终结果集合”（已完成其自身的 duplicatePolicy 去重）。将这些集合按 `extends` 声明顺序依次拼接，得到 imported_set。

### 5. 本层合并流水（严格顺序）

给定 imported_set（来自父层最终结果的并列拼接）：
1) include/exclude 过滤 imported_set：
   - includeTags：若设置，则仅保留“至少含任一 includeTags 的规则”；未设置或空，等价“不过滤（保留全部）”。
   - excludeTags：若设置，则从当前集合中移除“至少含任一 excludeTags 的规则”。
   - 二者次序：先 include 后 exclude。
   - 匹配规则：字符串完全匹配；规则 `tags` 为数组，采用 OR 语义（任一命中即生效）。无 `tags` 的规则在 include 阶段一律不命中（被排除）。
   - 重要：include/exclude 仅作用于 imported_set，不影响本地 `rules` 与 `extraRules`。
2) 追加本地 `rules`（local_set）到集合尾部。
3) 应用禁用集：
   - `disableById`：按 ID 精确移除集合中的匹配规则（若无匹配则忽略）。
   - `disableByTag`：移除集合中“至少含任一禁用标签”的规则。
   - 次序建议：先按 ID，后按 Tag（结果对等，但日志更易读）。
4) 追加 `extraRules`（extra_set）到集合尾部。
5) 依据本层 `duplicatePolicy` 做 ID 去重：
   - 比较键：`id`；若集合中出现同 ID 多次，视为重复。
   - 扫描顺序：严格按当前层“可见顺序”（extends 左→右 → 本地 rules → extraRules）。
   - `error`：一旦发现重复，报错并终止；报错需指明 JSON 路径与文件。
   - `warn_skip`：保留首次出现者，跳过其后的重复项；对每个被跳过项输出 warn（含文件与 JSON 指针）。
   - `warn_keep_last`：保留最后出现者，移除之前的所有同 ID 规则；对每个被覆盖项输出 warn。
6) 产出本层最终 result，向上传递给引用它的子层。

说明：父层在步骤 5) 已经完成其自身去重。因此 imported_set 内部“每位父文件”各自不再含重复，但“不同父文件之间”仍可能产生同 ID 冲突，统一由“本层 duplicatePolicy”处理。

### 6. `meta` 是否继承？duplicatePolicy 是否分层生效？

- `meta` 不继承（不转存）。父层的 `meta` 仅在其自身合并过程中生效；子层不会复制父层 `meta` 到自身结果。
- `duplicatePolicy` 为“分层策略”：
  - B 合并（extends A）时，先按 B 的 include/exclude/disable/extra 处理，再按 B 的 `duplicatePolicy` 去重，得到 `Result_B`。
  - C 合并（extends B）时，对 `Result_B` 再执行 C 的流程与 C 的 `duplicatePolicy` 去重，得到 `Result_C`。
  - D 合并（extends C）同理，使用 D 的 `duplicatePolicy` 产出最终结果 `Result_D`。
  - 这保证了每层都能用自己的策略解释“从父层引入 + 本层增量”的冲突。

### 7. includeTags/excludeTags 的跨层心智模型

心智模型：每一层只“投影（投片）”父层产物 imported_set。

- A 层的 includeTags/excludeTags 仅影响“它从更上层继承来的集合”，与 A 自己 `rules/extraRules` 无关；若 A 没有 `extends`，则其 include/exclude 不产生过滤效果（对 imported_set 的空集操作）。
- B 继承 A 时，B 接收到的是 A 的“最终结果”；A 已经对其 imported_set 完成了自己的过滤与去重。
- C 继承 B 时，C 可再次对“来自 B 的 imported_set”进行 include/exclude 过滤；其效果仅作用于“被引入的父集”，不会过滤 C 的本地 `rules/extraRules`。

示例（只关注标签投影）：

- A：`rules = {r1(tags:[taga]), r2(tags:[tagb])}`；A 无 `extends`，哪怕 `meta.includeTags=[taga]`，对 imported_set（空集）无影响，因此 A 的结果包含 r1 与 r2。
- B：`extends:[A]`，不带过滤；B 的 imported_set = {r1,r2}。
- C：`extends:[B]`，`meta.excludeTags=[taga]`；C 在 imported_set 上移除带 taga 的规则，得到 {r2}，再追加自己的本地规则，完成禁用/追加/去重。

结论：include/exclude 是“对父集的本层投影”，不具“跨层粘滞性”。若上层想要“只向下游暴露子集”，可将想暴露的规则拆分为独立父文件，供下游通过 include 选择；或由上层在自己的禁用阶段直接移除不希望向下游暴露的规则。

### 8. disableById/disableByTag 的跨层语义

- 禁用仅作用于“本层合并中的中间集合”（父集投影 + 本地 rules）；移除后不形成“禁用记忆”。
- 子层可以重新追加相同 ID 的规则（在其本地 rules 或 extraRules 中）。是否保留由“子层 duplicatePolicy 与冲突检测顺序”决定：
  - `warn_skip`：若父集中已经存在同 ID（且未被本层禁用），则后续追加会被跳过。
  - `warn_keep_last`：后续追加会覆盖父集同 ID 规则。
  - `error`：出现重复即报错。

### 9. 合并顺序与优先级（细节）

整体顺序（重要，用于解释冲突与日志次序）：
1) extends：按声明顺序 A → B → C … 拼接父层结果（各自已在其层内去重）。
2) imported_set 上执行 include → exclude。
3) 追加本地 rules。
4) 执行 disable（id → tag）。
5) 追加 extraRules。
6) 按 duplicatePolicy 去重（error | warn_skip | warn_keep_last）。

在 warn 策略下，为每个“被跳过/被覆盖”的规则输出一条 warn，内容含：策略名、冲突 ID、被影响项所在文件与 JSON 指针（如 `rules[3]`）。

### 10. 路径解析与错误定位

- 路径：
  - 绝对路径 `/...`：按绝对路径解析。
  - `./` 或 `../`：相对“当前 JSON 文件所在目录”。
  - 其他裸路径：若设置 `waf_jsons_dir` 则相对该目录；否则相对 Nginx prefix。
- 错误定位：
  - JSON 语义错误（缺字段/非法类型/非法组合）与继承错误（循环/深度）均需返回“文件 + JSON pointer”。
  - duplicatePolicy=error 时，重复 ID 的每一处冲突都应指出“后出现项”的 JSON 指针与文件。

### 11. 复杂示例（D 继承 C 继承 B 继承 A）

设：所有文件均只有 `rules/tags/id`，便于说明。`→` 表示拼接顺序。

- A（无 extends）：
  - rules: [ a1{id:1,tags:[x]}, a2{id:2,tags:[y]} ]
  - meta: { duplicatePolicy: warn_skip }
  - 结果 A = [a1, a2]

- B（extends: [A]）：
  - imported_set = [a1, a2]
  - meta: { includeTags: [x], duplicatePolicy: warn_keep_last }
  - include 过滤 imported_set：仅保留含 x → [a1]
  - 追加本地 rules: [ b1{id:2,tags:[y]} ]
  - disable: 无
  - 追加 extra: 无
  - 去重（keep_last）：冲突 ID=2 不存在；结果 B = [a1, b1]

- C（extends: [B]）：
  - imported_set = [a1, b1]
  - meta: { excludeTags: [x], duplicatePolicy: error }
  - exclude 过滤 imported_set：移除含 x → [b1]
  - 追加本地 rules: [ c1{id:1,tags:[z]} ]
  - disable: 无
  - 追加 extra: 无
  - 去重（error）：集合含 id=1 与 id=2 各一次，无冲突 → 结果 C = [b1, c1]

- D（extends: [C]）：
  - imported_set = [b1, c1]
  - meta: { duplicatePolicy: warn_skip }
  - include/exclude: 无
  - 追加本地 rules: [ d1{id:1,tags:[w]} ]
  - disable: 无
  - 追加 extra: 无
  - 去重（skip）：遇到 id=1 的重复（c1 与 d1），保留先出现的 c1，跳过 d1 → 最终结果 D = [b1, c1]

该例展示：
- 各层 duplicatePolicy 仅对“本层的中间集合”生效；父层已完成其自身去重。
- include/exclude 仅投影父集，不影响本地 rules/extra。
- 下层可通过本地追加 + duplicatePolicy 改变父集冲突的取舍。

### 12. 与 M1 实装步骤对齐

与 `docs/refactor-plan-v2.md` 第六章“解析与合并（yyjson_mut_doc）”一致：
1) 解析当前 JSON（容错）。
2) 递归处理 extends（左→右），检测循环与深度上限。
3) 对“被引入规则集合”应用 include/exclude 过滤（仅作用 imported_set）。
4) 追加当前文件 rules。
5) 应用 disableById/disableByTag。
6) 追加 extraRules。
7) 依据 duplicatePolicy 处理冲突 id（默认 warn_skip）。

日志/错误格式与测试脚本已对齐（参见 `dev/m1_json_merge_tests.sh`）——例如：
```
waf: duplicate rule id=700 at <file>, skip (policy=warn_skip)
```

### 13. 设计 FAQ

Q1：为什么 include/exclude 不作用于本地 rules？
- A：本意是“挑选父集的一部分”，避免“本地规则被误删”带来理解成本；若确需删本地规则，使用 `disableById/Tag` 更直观。

Q2：禁用是否会“传给子层”？
- A：不会。禁用仅是“本层合并结果上的一次移除”。子层若再次追加相同 ID 是否生效，由子层 duplicatePolicy 决定。

Q3：同一层多父文件产生的重复如何解释？
- A：本层 duplicatePolicy 负责该层的所有重复，包括“不同父文件之间”的重复与“父集 vs 本地/额外”的重复。

Q4：没有 `extends` 时，include/exclude 是否无效？
- A：是。无父集可投影时，这两个字段不会产生过滤效果（属于幂等设置）。


### 14. extraRules 必要性

简短结论：extraRules 是有必要的。它不是“重复的 rules”，而是“后置补丁/覆盖通道”，与本层的 disable/顺序/覆盖策略形成清晰的两段式语义。

为什么需要 extraRules（相对本层 rules）：
- 核心差异（顺序与作用域）
  - 本层合并顺序：父集投影(include→exclude) → 追加 rules → 本层禁用(disableById/Tag) → 追加 extraRules → duplicatePolicy 去重。
  - 也就是说，disable 只作用于“父集 + 本地 rules”的中间集合，不作用于 extraRules；而 extraRules 在禁用之后、去重之前追加。
- 关键价值
  - 明确的“后置补丁位”：当你用 disableByTag/Id 做了批量清扫后，仍可在 extraRules 精准补回或新增规则，不会被本层的禁用再次移除。
  - 可控的覆盖行为：与 duplicatePolicy 搭配实现不同策略。
    - warn_keep_last：在 extraRules 放同 ID，可“最后覆盖”父集或本地 rules（有 warn 提示，便于审计）。
    - warn_skip：extraRules 变为“保守追加”（若已存在同 ID 则自动跳过），适合低风险热补。
    - error：禁止覆盖，强制显式处理冲突。
  - 职责分离与协作：约定“rules=基线规则，extraRules=环境/热修/自动化追加”，便于不同角色协作与审阅（生成器或 CI 只动 extraRules，不扰动基线排序与结构）。
  - 运维友好：需要临时上线/下线某些规则时，集中用 disable 管批量、用 extraRules 做小范围回补或替换，变更清晰可控。

若没有 extraRules，会发生什么：
- 只能把“补丁”也放在 rules，但它会被同层的 disable 冲掉（尤其是按 Tag 的粗粒度禁用），需要反复调顺序或引入更复杂的禁用语义，心智负担更重。
- 无法自然地表达“先整体禁用一类，再补回少量精修”的常见需求，且覆盖/跳过的策略难以独立控制。

推荐用法（实践建议）：
- 父/库文件只维护 rules。业务/环境入口文件：先用 disable 扫描父集+本地基线，再在 extraRules 放置热修、例外或“最后覆盖”规则；需要覆盖则选择 keep_last，需要安全追加则用 skip，需要强约束则用 error。
- 把“短期热修/A/B 验证”的规则放 extraRules，回收时一键删除 extraRules 段即可，避免污染基线 rules。

因此，extraRules 提供了与 disable、duplicatePolicy、顺序模型相配合的“后置补丁层”。这层让批量禁用与小范围回补、覆盖策略、协作分工三件事同时变得简单且可审计。

—— 完 ——





