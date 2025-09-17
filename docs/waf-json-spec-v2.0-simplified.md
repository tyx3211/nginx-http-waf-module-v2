## Nginx HTTP WAF v2.0 简化版规则规范（数据面 M1）

本规范定义 v2.0（首版）规则 JSON 的最小合并语义，聚焦“够用、低心智负担、便于控制台可视化”。更丰富的阶段化过滤与补丁位请参考 v2.1 扩展草案（见 `waf-json-inheritance-merge-spec.md`）。

### 1. 总览

- 顶层字段：
  - `meta.extends`: 字符串或对象数组，父规则文件（相对/绝对路径）；可递归。对象形态可声明导入级 target 重写。
  - `rules`: 当前文件自有规则数组。
  - `disableById`: 数组，禁用继承规则的 ID（仅作用 imported_set）。
  - `disableByTag`: 数组，禁用继承规则的标签（仅作用 imported_set）。
  - `meta.duplicatePolicy`: 去重策略：`error | warn_skip | warn_keep_last`（默认 `warn_skip`）。
- 明确不支持（v2.0 移除）：`meta.includeTags`、`meta.excludeTags`、`extraRules`。
- `meta` 不跨层继承；仅入口 JSON 的 `meta` 保留在最终产物中用于标识信息。

### 2. 字段规范与继承规则（OpenAPI 风格）

本节定义所有可出现字段的类型、必填性、默认值、取值范围、继承与生效规则。若与 v2.1 扩展草案（`waf-json-inheritance-merge-spec-v2.1.md`）存在差异，以本 v2.0 简化规范为准。

- 顶层对象类型：`object`
- 允许注释与尾逗号：是（容错解析）。
- 未声明字段的处理：忽略（不报错，不参与合并）。

2.1 顶层字段

- version
  - 类型：`number`
  - 必填：否；默认值：1（未提供时按 1 处理）
  - 继承：不继承；仅入口 JSON 透传到最终产物（如需）
  - 作用域：标识规则文件版本；不参与合并与去重

- meta
  - 类型：`object`
  - 必填：否；默认：缺省为空对象
  - 继承：不跨层拷贝；每层仅在自身合并过程中读取其 `meta` 控制项；最终产物的 `meta` 取自入口 JSON
  - 字段：
    - name
      - 类型：`string`
      - 必填：否；默认：无
      - 继承：不继承；最终产物保留入口 JSON 的该值（便于标识）
      - 作用域：标识用途
    - versionId
      - 类型：`string`
      - 必填：否；默认：无
      - 继承：不继承；最终产物保留入口 JSON 的该值
      - 作用域：版本标识/对账
    - tags
      - 类型：`string[]`
      - 必填：否；默认：无
      - 继承：不继承；仅作为文件级标签信息（当前未用于合并控制）
    - extends
      - 类型：`Array<string | object>`（文件路径或带重写配置的对象）
      - 必填：否；默认：空数组
      - 继承：不继承；仅在当前层解析时使用
      - 作用域：声明父规则文件列表；按左→右顺序递归解析并拼接父层“最终结果集合”形成 imported_set；当元素为对象形态时，可对来自该文件的规则应用“导入级 target 重写”。
      - 路径解析：绝对路径原样；以 `./`、`../` 开头者相对当前 JSON 文件目录；其他裸路径相对 `waf_jsons_dir`（若设置）否则相对 Nginx prefix
      - 对象形态字段：
        - `file: string`（必填）父规则文件路径
        - `rewriteTargetsForTag?: Record<string, Target[]>`（可选）按标签批量重写目标
        - `rewriteTargetsForIds?: Array<{ ids: number[]; target: Target[] }>`（可选）按 ID 批量重写目标
        - 说明：重写仅作用于本层 imported_set，不回写父文件。
    - duplicatePolicy
      - 类型：`"error"|"warn_skip"|"warn_keep_last"`
      - 必填：否；默认：`warn_skip`
      - 继承：不继承；分层生效（每层在自身合并结束时执行一次该策略）
      - 作用域：对“本层可见集合（父集拼接→禁用→本地追加）”按出现顺序进行 ID 去重

- disableById
  - 类型：`number[]`（整数 ID）
  - 必填：否；默认：空数组
  - 继承：不继承；仅在当前层对 imported_set 生效
  - 作用域：仅移除 imported_set 中 ID 命中的规则；不影响本地 `rules`

- disableByTag
  - 类型：`string[]`
  - 必填：否；默认：空数组
  - 继承：不继承；仅在当前层对 imported_set 生效
  - 匹配：规则项 `tags` 为 `string[]`，采用 OR 语义（至少包含任一禁用标签即移除）

- rules
  - 类型：`Rule[]`
  - 必填：是（若为空数组则表示“无本地规则”）
  - 继承：不继承（父层结果通过 `meta.extends` 引入，不复制父层 `rules` 字段本身）
  - 作用域：本地规则集合；在禁用 imported_set 之后追加到集合尾部，再参与去重

- policies
  - 类型：`object`
  - 必填：否；默认：无
  - 继承：不继承字段值；最终产物保留入口 JSON 中的该对象（在 v2.0 中透传，不参与 M1 合并）
  - 作用域：运行期策略（M2 处理）。例如 `dynamicBlock` 等；本版仅透传。

2.2 规则项 Rule

- id：`number`（必填）
- tags：`string[]`（可选；默认空）
- phase：`"ip_allow"|"ip_block"|"uri_allow"|"detect"`（可选；默认由 `target/action` 在编译期推断，v2.0 不强制）
- target：`Target | Target[]`（必填）
  - `Target` 取值：`"CLIENT_IP"|"URI"|"ALL_PARAMS"|"ARGS_COMBINED"|"ARGS_NAME"|"ARGS_VALUE"|"BODY"|"HEADER"`
  - 当为数组时，表示同一条规则在数组内每个目标上独立评估；匹配日志记录命中的 `effectiveTarget`
  - 语法糖：`ALL_PARAMS` 在加载期等价展开为 `["URI","ARGS_COMBINED","BODY"]`
  - 约束：当包含 `HEADER` 时，数组长度必须为 1，且需同时提供 `headerName`
- headerName：`string`（当 `target=HEADER` 时必填，否则禁止出现）
- match：`"CONTAINS"|"REGEX"|"CIDR"`（必填）
- pattern：`string | string[]`（必填；数组为 OR 语义；必须非空）
- caseless：`boolean`（可选；默认 false）
- action：`"DENY"|"LOG"|"BYPASS"`（必填）
- score：`number`（可选；默认 10；当 action=BYPASS 忽略；编译期校验）
- priority：`number`（可选；默认 0；仅检测段内部排序使用）

继承与去重：Rule 不直接“继承”；父层产物经 imported_set 引入后，与本地 Rule 合并并受 `meta.duplicatePolicy` 管控。重复比较键为 `id`。

2.3 继承与生效矩阵（摘要）

- 不跨层保留到最终产物：`meta.*`（仅入口 JSON 保留）、`disableById`、`disableByTag`
- 分层生效：`meta.duplicatePolicy`
- 通过父集引入：父层“最终结果集合”（规则条目本身）
- 仅入口透传：`version`、`meta.name`、`meta.versionId`、`policies`（本版透传）

注：v2.0 简化规范不支持 `meta.includeTags`、`meta.excludeTags`、`extraRules`。

---

### 3. 合并流水（严格顺序）

1) 解析入口 JSON（允许注释/尾逗号）。
2) 递归解析 `meta.extends`（左→右），环检测与深度上限（由 `waf_json_extends_max_depth` 控制，0 表示不限）。
3) 生成 imported_set：按声明顺序拼接各父文件的“最终结果集合”。
4) 应用导入级 target 重写（若 `meta.extends` 中使用了对象形态）：
   - 按文件来源匹配 → 依次应用 `rewriteTargetsForTag` 与 `rewriteTargetsForIds`
   - 校验：重写后 `target` 必须符合 Rule 的取值与约束（含 `HEADER` 限制、`ALL_PARAMS` 展开）
5) 对 imported_set 应用禁用：
   - `disableById`: 精确移除匹配 ID 的规则。
   - `disableByTag`: 移除含任一禁用标签的规则。
   - 注意：禁用仅作用 imported_set，不影响本地 `rules`。
6) 追加本地 `rules` 至集合尾部。
7) 依据 `duplicatePolicy` 去重：比较键为 `id`，按可见顺序处理冲突：
   - `error`: 发现重复直接报错。
   - `warn_skip`: 保留首次，跳过其后（默认）。
   - `warn_keep_last`: 保留最后，覆盖之前。

产出最终 `rules` 数组；其它字段（如 `version`、`meta.name/versionId`、`policies`）若存在则从入口 JSON 透传。

### 4. 字段语义与约束

- `rules` 中每条规则至少包含：`id`（整数）、`target`、`match`、`pattern`、`action`；校验细则在后续编译/检测阶段完善。
- `disableById/disableByTag` 仅过滤 imported_set；不影响本地 `rules`。不想要的本地规则可直接删除。
- `duplicatePolicy` 为分层策略：每层在自己的合并完成后执行一次去重，然后将“本层最终结果”作为子层的父集输入。

### 5. 路径解析与错误

- 路径：绝对路径按原样；`./`、`../` 相对当前 JSON 所在目录；裸路径相对 `waf_jsons_dir`（若设置）否则相对 Nginx prefix。
- 错误：
  - 继承环或深度超限：报错并定位到文件；
  - 重复策略为 `error` 且冲突：报错并包含文件与 JSON 指针（若可用）。

### 6. 示例（entry 继承 base 与 child）

- base.rules: [100{tags:[xss]}, 200{tags:[legacy,blockedTag]}]
- child.rules: [300{tags:[xss]}, 200{tags:[xss]}]
- entry:
  - meta: { extends: ["./base.json", "./lib/child.json"], duplicatePolicy: "warn_keep_last" }
  - disableById: [200]
  - disableByTag: ["blockedTag"]
  - rules: [400{tags:[entry]}, 200{tags:[entry]}]

合并过程：
- imported_set 初始：[100,200(base),300,200(child)]
- 禁用后（对 imported_set）：去掉 id=200 与含 blockedTag 的 200(base) → [100,300]
- 追加本地 rules → [100,300,400,200(entry)]
- 去重（keep_last）：无冲突需要处理 → 最终结果为 4 条。

—— 完 ——


### 8. Target 数组、导入级重写与日志（实现指引）

本节为实现与控制台展示的指导性说明，不构成强制规范；用于统一心智模型，降低使用门槛。

8.1 Target 数组
- 语义：`target: string[]` 表示同一规则对多个目标独立评估；匹配日志写入命中的 `effectiveTarget`。
- 语法糖：`ALL_PARAMS` 在加载期展开为 `URI|ARGS_COMBINED|BODY` 三者；无需手写数组。
- 约束：包含 `HEADER` 时，数组长度必须为 1，且需提供 `headerName`。

8.2 导入级重写（针对 imported_set）
- 入口 JSON 的 `meta.extends` 可使用对象形态，按文件来源对父集应用 target 重写：
  - `rewriteTargetsForTag: { "apply:multi-surface": ["URI","ARGS_COMBINED","BODY"] }`
  - `rewriteTargetsForIds: [{ ids: [101,102], target: ["ARGS_COMBINED","BODY"] }]`
- 重写仅改变当前层 imported_set 的规则目标，不影响父文件内容；随后再执行禁用与本地规则追加。
- 标签不具备特殊语义，`apply:multi-surface` 仅为一种约定俗成的提示标签；任何标签均可用作选择器。

8.3 运行期日志与编译期元信息（可选增强）
- 日志建议包含：`ruleId`、`effectiveTarget`、`action`、`score`、`importedFrom`（若可用）。
- 当发生重写时，建议额外记录：`originalTarget` 与 `rewriteSource`（如 `via=tag|ids`，以及匹配到的标签或 ID 列表）。
- 为便于排查，可在构建后的内存结构或导出调试 JSON 中注入供应商扩展字段（OpenAPI 风格）：
  - 规则级 `x-originalTarget`、`x-effectiveTarget`、`x-rewriteInfo`（含来源文件、匹配选择器）。

8.4 控制台展示建议
- 以 imported_set 分组：每个父文件一块，显示规则数与“已应用重写/禁用”统计。
- 将“重写 targets”放在该分组的“高级”入口；进入后展示该父集出现过的所有标签便于选择；若检测到 `apply:multi-surface`，提供温馨提示可一键重写。
- 提供预览与回滚：对比“父集→应用重写→最终目标”的变化；支持 Reset。
- 校验即时反馈：当选择 `HEADER` 同时勾选了其他目标时给出错误提示；`ALL_PARAMS` 自动展开为三项。


### 7. 与 v1 行级 DSL 的映射与差异对照

本节辅助从 `nginx-http-waf-module` v1 行级 DSL（见仓库 `README.md` 中 4.2“WAF 规则定义”）迁移到 v2 JSON 规范。由于 v2 进行了结构化与分层合并设计，以下对照为“语义映射”，不追求逐字段死板对应。

7.1 字段语义对照（摘要）

- 规则标识：
  - v1 `id_number:` → v2 `id:number`（同一集合内唯一，用于去重与引用）
  - 等价性：强等价

- 检测目标：
  - v1 `TARGET`（URI | ARGS_COMBINED | ARGS_NAME | ARGS_VALUE | BODY | HEADER "Name" | ALL_PARAMS | COMMON_SET）
  - v2 `target` 支持 `string | string[]`；当 `target=HEADER` 时补充 `headerName:string`
  - 等价性：强等价并增强（`COMMON_SET` 不再作为运行期语义；建议用显式 `target[]` 或导入级重写表达）

- 匹配类型：
  - v1 `MATCH_TYPE`（CONTAINS | REGEX）
  - v2 `match`（CONTAINS | REGEX | CIDR），新增 `CIDR` 以配合 IP 类规则
  - 等价性：强等价（并向上兼容）

- 模式：
  - v1 `"PATTERN"`（单值）
  - v2 `pattern: string | string[]`（数组表示 OR 关系）
  - 等价性：强等价（v2 更灵活）

- 大小写：
  - v1 `CASELESS` 可选标记
  - v2 `caseless: boolean`（默认 false）
  - 等价性：强等价

- 动作：
  - v1 `ACTION`（DENY | LOG）
  - v2 `action`（DENY | LOG | BYPASS）
  - 等价性：强等价（并新增 BYPASS）

- 计分：
  - v1 `SCORE number`
  - v2 `score: number`（默认 10）
  - 等价性：强等价

- 优先级：
  - v1 无显式优先级（由文件内顺序与子模块顺序决定）
  - v2 `priority: number`（可选，细化检测段内部排序），默认 0
  - 等价性：新增能力

- 标签：
  - v1 无通用标签字段
  - v2 `tags: string[]`
  - 等价性：新增能力（便于批量禁用/可视化）

- 继承与合并：
  - v1 通过 Nginx 指令装配多个规则文件，运行时合并；无显式“继承/禁用”语义
  - v2 通过 `meta.extends` 声明父集；支持 `disableById/disableByTag`、分层 `meta.duplicatePolicy`
  - 等价性：v2 为增强能力

7.2 示例转换

- v1 → v2（基础匹配）

  v1：
  ```
  200004: ALL_PARAMS CONTAINS "eval(" DENY 20
  ```

  v2：
  ```json
  {
    "id": 200004,
    "target": "ALL_PARAMS",
    "match": "CONTAINS",
    "pattern": "eval(",
    "action": "DENY",
    "score": 20
  }
  ```

- v1 HEADER → v2（带 headerName）

  v1：
  ```
  200003: HEADER "User-Agent" CONTAINS "BadBot" LOG 1
  ```

  v2：
  ```json
  {
    "id": 200003,
    "target": "HEADER",
    "headerName": "User-Agent",
    "match": "CONTAINS",
    "pattern": "BadBot",
    "action": "LOG",
    "score": 1
  }
  ```

- v1 REGEX + CASELESS → v2（caseless 布尔）

  v1：
  ```
  URI REGEX "(?i)select.*from"
  ```

  v2：
  ```json
  {
    "id": 200001,
    "target": "URI",
    "match": "REGEX",
    "pattern": "select.*from",
    "caseless": true,
    "action": "DENY",
    "score": 50
  }
  ```

- v1 多条同构规则 → v2 单条数组模式（OR）

  v1：
  ```
  BODY CONTAINS "<script>" DENY 15
  BODY CONTAINS "</script>" DENY 15
  ```

  v2：
  ```json
  {
    "id": 200002,
    "target": "BODY",
    "match": "CONTAINS",
    "pattern": ["<script>", "</script>"],
    "action": "DENY",
    "score": 15
  }
  ```

7.3 迁移建议与注意事项（清单）

- 确认 ID 域与唯一性：对每个 v1 规则文件分配不重叠的 `id` 段，避免 v2 去重冲突。
- 明确 headerName：将 v1 中 `HEADER "Name"` 显式拆分为 `target=HEADER` + `headerName`。
- 正则大小写：将 v1 的 `(?i)` 或 `CASELESS` 统一映射为 `caseless: true`，建议同时去掉正则内的 `(?i)` 以避免双重语义。
- 模式合并：相同语义的多条 CONTAINS/REGEX 可用 `pattern: []` 合并，减少条目数。
- 标签治理：为规则补充 `tags`（如 `xss`、`sqli`、`legacy`、`entry`），便于后续 `disableByTag` 与可视化分组。
- 分层装配：使用 `meta.extends` 组织公共基线与业务特例；在入口层使用 `disableById/disableByTag` 做裁剪，避免复制编辑父文件。
- 去重策略：默认 `meta.duplicatePolicy=warn_skip`；当需要“本地覆盖父级同 ID”时，设置为 `warn_keep_last` 并在本地尾部追加覆盖条目。
- CIDR 模式：将 v1 的 IP/CIDR 黑白名单迁移到 v2 时，可用 `target=CLIENT_IP` + `match=CIDR`；出于语义清晰，建议放在独立文件并通过 `phase=ip_allow/ip_block`（若使用）。
- 透传策略：`policies` 对象在 v2.0 不参与合并，仅入口透传；不要在父层定义期望入口聚合的策略。

7.4 等价性等级说明

- 强等价：字段/语义一一对应，迁移仅是字段名与结构调整（如 `TARGET`、`MATCH_TYPE`、`ACTION`、`SCORE`、`CASELESS`）。
- 宽等价：语义相近但 v2 更强（如 `pattern` 支持数组、`action` 新增 `BYPASS`、新增 `priority`、`tags`）。
- 增强能力：v1 无直接对应（如 `meta.extends`、`disableById/disableByTag`、`meta.duplicatePolicy`、`CIDR` 匹配）。

