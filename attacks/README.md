# IShield 红队攻击脚本库

三类攻击场景，**默认每类约 500 条**（程序化生成 + 去重），每类包含：

| 内容 | 文件 |
|------|------|
| 对抗样本 + 越狱用例 + 攻击链定义 | `scenario*/cases.json` |
| 智能体攻击脚本 | `scenario*/attack_agent.py` |

## 场景说明

| 场景 | 目录 | 攻击入口 | 说明 |
|------|------|----------|------|
| 一、提示注入与越狱 | `scenario1_prompt_injection/` | `/api/detect` | 指令覆盖、DAN、角色扮演等 |
| 二、工具调用劫持 | `scenario2_tool_hijacking/` | `/api/simulate` | SQL 注入、钓鱼邮件、路径遍历 |
| 三、记忆中毒 | `scenario3_memory_poisoning/` | `/api/detect` + simulate | 伪造记忆、跨会话、多轮污染 |

## 快速运行

```bash
# 1. 启动 IShield
cd backend && python app.py

# 2. 另开终端 — 运行全部三类攻击（每场景 500 条，默认运行时生成）
python attacks/run_all_attacks.py
python attacks/run_all_attacks.py --count 500

# 3. 预生成并保存 cases.json（可选，便于离线复现）
python attacks/case_generator.py --count 500 --save

# 4. 或单独运行某一场景
python attacks/scenario1_prompt_injection/attack_agent.py --count 500
python attacks/scenario2_tool_hijacking/attack_agent.py --count 500 --save-cases
python attacks/scenario3_memory_poisoning/attack_agent.py --use-file  # 使用已有 cases.json
```

## 输出报告

- `attacks/reports/scenario1_prompt_injection_report.json`
- `attacks/reports/scenario2_tool_hijacking_report.json`
- `attacks/reports/scenario3_memory_poisoning_report.json`
- `attacks/reports/all_scenarios_summary.json`

> 场景一通过 `/api/detect` 测试；若配置了 DeepSeek 等 API，每条约 1～2s。
> 场景二/三工具链走 `/api/simulate`，通常拦截率更高（规则+策略）。

## 用例规模（每场景，默认 `--count 500`）

由 `attacks/case_generator.py` 生成，大致比例：

| 类型 | 约占比 | 说明 |
|------|--------|------|
| 对抗样本 | ~60% | 子串/编码/角色扮演等变体 |
| 越狱用例 | ~25–30% | DAN、多轮、工具诱导等 |
| 智能体攻击链 | 余量 | 多步 detect / simulate |

手工 `cases.json`（约 25 条）仍可用 `--use-file` 加载。

## cases.json 字段

```json
{
  "adversarial_samples": [{"id", "text|tool+params", "expected", "type"}],
  "jailbreak_cases": [{"id", "mode", "text|turns|tool", "expected"}],
  "agent_attack_chains": [{"id", "name", "steps": [{"action", ...}]}]
}
```
