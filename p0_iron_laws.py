"""
P0 铁律规则引擎 (Iron Laws Enforcement)

Hermes Agent 的自我约束与治理系统。
将 34 条铁律转化为可执行的代码规则，在运行时自动检查、拦截、记录。

设计原则:
  - 每条规则都是可执行的函数，不是文档注释
  - 违规时自动拦截、记录、告警
  - 规则可按场景启用/禁用
  - 所有判断有迹可循（结构化日志）

文档规范: docs/p0_iron_laws.md
"""

import json
import logging
import time
import hashlib
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set, Tuple
from dataclasses import dataclass, field
from enum import Enum
from datetime import datetime

logger = logging.getLogger("P0IronLaws")

# ──────────────────────────────────────────────
# 数据结构
# ──────────────────────────────────────────────

class Severity(Enum):
    """违规严重程度"""
    P0_CRITICAL = "P0_CRITICAL"       # 立即拦截，不可恢复
    P1_BLOCKING = "P1_BLOCKING"       # 拦截但可手动放行
    P2_WARNING = "P2_WARNING"         # 警告但继续执行
    P3_INFO = "P3_INFO"              # 仅记录


class RuleCategory(Enum):
    """规则分类（对应铁律5个层级）"""
    UNDERSTANDING = "understanding"   # 第一层：理解与决策 (1-7)
    EXECUTION = "execution"           # 第二层：执行与验证 (8-12)
    GOVERNANCE = "governance"         # 第三层：规则治理 (13-19)
    TASK_PROGRESS = "task_progress"   # 第四层：任务推进 (20-24)
    EVOLUTION = "evolution"           # 第五层：进化与治理 (25-34)


@dataclass
class RuleViolation:
    """违规记录"""
    rule_id: str                     # 规则编号，如 "L001"
    rule_name: str                   # 规则名称
    severity: Severity               # 严重程度
    category: RuleCategory           # 分类
    message: str                     # 违规描述
    context: Dict[str, Any] = field(default_factory=dict)  # 上下文
    timestamp: float = field(default_factory=time.time)
    action_taken: str = ""           # 采取的行动: blocked/warned/ignored
    recovery_path: str = ""          # 修复建议


@dataclass
class RuleResult:
    """规则检查结果"""
    rule_id: str
    passed: bool
    violation: Optional[RuleViolation] = None
    details: str = ""


# ──────────────────────────────────────────────
# 规则基类
# ──────────────────────────────────────────────

class BaseRule:
    """所有 P0 规则的基类"""

    rule_id: str = ""
    rule_name: str = ""
    severity: Severity = Severity.P0_CRITICAL
    category: RuleCategory = RuleCategory.EXECUTION
    description: str = ""
    enabled: bool = True

    def check(self, context: Dict[str, Any]) -> RuleResult:
        """
        检查规则是否被遵守。
        子类必须实现。
        """
        raise NotImplementedError(f"{self.__class__.__name__}.check() must be implemented")


# ──────────────────────────────────────────────
# 第一层：理解与决策 (L001-L007)
# ──────────────────────────────────────────────

class L001_GoalFirstRule(BaseRule):
    """
    铁律1: 最高目标铁律
    第一目标永远不是"回复用户"，而是：理解目标 → 拆解 → 推进 → 验证 → 沉淀。
    """
    rule_id = "L001"
    rule_name = "最高目标铁律"
    severity = Severity.P1_BLOCKING
    category = RuleCategory.UNDERSTANDING
    description = "检查是否直接跳入回复而未经理解-拆解-规划流程"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        user_input = context.get("user_input", "")
        has_decomposition = context.get("has_decomposition", False)
        response = context.get("response", "")

        # 如果用户输入很长（>50字符），但没有分解步骤就回复 → 违规
        if len(user_input) > 50 and not has_decomposition:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"复杂输入 ({len(user_input)} 字符) 未进行目标分解就直接回复",
                context={"input_length": len(user_input), "response_length": len(response)},
                action_taken="warned",
                recovery_path="复杂任务应先拆解: 目标/阶段/依赖/风险/优先级/交付物"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="未进行目标分解")

        return RuleResult(rule_id=self.rule_id, passed=True, details="规则遵守")


class L002_DeepUnderstandingRule(BaseRule):
    """
    铁律2: 自然语言深度理解铁律
    识别：显式意图/隐含意图/关键对象/约束/上下文/缺失信息/歧义/真实目标。
    """
    rule_id = "L002"
    rule_name = "自然语言深度理解铁律"
    severity = Severity.P1_BLOCKING
    category = RuleCategory.UNDERSTANDING
    description = "检查是否对输入进行了结构化意图分析"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        intent = context.get("parsed_intent", {})

        required_fields = ["explicit_intent", "constraints", "expected_result"]
        missing = [f for f in required_fields if f not in intent or not intent[f]]

        if missing:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"意图分析缺失关键字段: {', '.join(missing)}",
                context={"intent": intent, "missing_fields": missing},
                action_taken="warned",
                recovery_path="结构化输入: intent/entities/constraints/context/ambiguity/expected_result/next_step"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details=f"缺失字段: {missing}")

        return RuleResult(rule_id=self.rule_id, passed=True, details="意图分析完整")


class L003_StructuredParsingRule(BaseRule):
    """
    铁律3: 结构化理解铁律
    输入必须先结构化: intent/entities/constraints/context/ambiguity/expected_result/next_step。
    """
    rule_id = "L003"
    rule_name = "结构化理解铁律"
    severity = Severity.P2_WARNING
    category = RuleCategory.UNDERSTANDING
    description = "检查输入是否经过结构化解析"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        structured = context.get("structured_input", {})
        if not structured:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message="输入未经结构化解析",
                context={"raw_input_length": len(context.get("user_input", ""))},
                action_taken="warned",
                recovery_path="先解析再执行: intent → entities → constraints → context → next_step"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="输入未结构化")

        return RuleResult(rule_id=self.rule_id, passed=True, details="输入已结构化")


class L004_UncertaintyExplicitRule(BaseRule):
    """
    铁律4: 不确定性显式化铁律
    区分：已知事实/推测内容/未知内容/缺失条件/可推进部分/暂无法推进部分。
    禁止把猜测说成事实。
    """
    rule_id = "L004"
    rule_name = "不确定性显式化铁律"
    severity = Severity.P0_CRITICAL
    category = RuleCategory.UNDERSTANDING
    description = "检查输出是否将推测内容标记为事实"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        response = context.get("response", "")
        has_speculation_markers = context.get("has_speculation_markers", False)
        uncertainty_map = context.get("uncertainty_map", {})

        # 如果回复包含绝对断言但没有置信度标记
        if not has_speculation_markers and uncertainty_map.get("speculative_count", 0) > 0:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"输出包含 {uncertainty_map['speculative_count']} 处推测但未标记不确定性",
                context={"uncertainty_map": uncertainty_map},
                action_taken="blocked",
                recovery_path="明确标注: 已知事实 vs 推测 vs 未知。禁止把猜测说成事实。"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="推测内容未标记")

        return RuleResult(rule_id=self.rule_id, passed=True, details="不确定性已标注")


class L005_MultiIntentRule(BaseRule):
    """
    铁律5: 多意图识别铁律
    识别：主意图/次意图/长期意图/背后真实目标。
    不得将复杂自然语言压缩成单一粗暴理解。
    """
    rule_id = "L005"
    rule_name = "多意图识别铁律"
    severity = Severity.P2_WARNING
    category = RuleCategory.UNDERSTANDING
    description = "检查是否识别了多意图输入中的多个意图"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        intents = context.get("detected_intents", [])
        user_input = context.get("user_input", "")

        # 输入包含多个动作词但没有检测到多个意图 → 可能遗漏
        action_verbs = ["看", "查", "改", "跑", "重启", "扫", "写", "推", "存", "删", "建", "查", "找"]
        detected_verbs = [v for v in action_verbs if v in user_input]

        if len(detected_verbs) >= 2 and len(intents) < 2:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"输入包含 {len(detected_verbs)} 个动作 ({', '.join(detected_verbs)}) 但只识别了 {len(intents)} 个意图",
                context={"detected_verbs": detected_verbs, "intents": intents},
                action_taken="warned",
                recovery_path="多动词输入需要识别主意图+次意图+长期意图+背后真实目标"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="多意图可能遗漏")

        return RuleResult(rule_id=self.rule_id, passed=True, details="意图识别完整")


class L006_ContextBindingRule(BaseRule):
    """
    铁律6: 上下文绑定铁律
    结合：当前对话/历史任务/用户偏好/系统状态/已有规则经验。
    禁止"每一句都像第一次见到"。
    """
    rule_id = "L006"
    rule_name = "上下文绑定铁律"
    severity = Severity.P1_BLOCKING
    category = RuleCategory.UNDERSTANDING
    description = "检查是否加载了相关上下文和历史"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        has_context = context.get("context_loaded", False)
        has_memory = context.get("memory_checked", False)
        has_user_prefs = context.get("user_prefs_loaded", False)

        missing_context = []
        if not has_context:
            missing_context.append("当前对话上下文")
        if not has_memory:
            missing_context.append("历史任务记忆")
        if not has_user_prefs:
            missing_context.append("用户偏好")

        if missing_context:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"未加载上下文: {', '.join(missing_context)}",
                context={"has_context": has_context, "has_memory": has_memory, "has_user_prefs": has_user_prefs},
                action_taken="warned",
                recovery_path="执行前先加载: 当前对话 → 历史记忆 → 用户偏好 → 系统状态 → 已有规则"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details=f"缺失上下文: {missing_context}")

        return RuleResult(rule_id=self.rule_id, passed=True, details="上下文完整")


class L007_GoalAlignmentRule(BaseRule):
    """
    铁律7: 目标对齐铁律
    所有理解最终回到："用户最终要达成什么结果？"
    """
    rule_id = "L007"
    rule_name = "目标对齐铁律"
    severity = Severity.P1_BLOCKING
    category = RuleCategory.UNDERSTANDING
    description = "检查输出是否与用户最终目标对齐"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        user_goal = context.get("user_goal", "")
        response_addresses_goal = context.get("response_addresses_goal", False)

        if user_goal and not response_addresses_goal:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"输出未对齐用户目标: {user_goal}",
                context={"user_goal": user_goal},
                action_taken="warned",
                recovery_path="每个回答都要回到: 用户最终要达成什么结果？"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="未对齐用户最终目标")

        return RuleResult(rule_id=self.rule_id, passed=True, details="目标对齐")


# ──────────────────────────────────────────────
# 第二层：执行与验证 (L008-L012)
# ──────────────────────────────────────────────

class L008_ExecutionLoopRule(BaseRule):
    """
    铁律8: 执行闭环铁律
    闭环：感知 → 理解 → 结构化 → 规划 → 执行 → 验证 → 记录 → 复盘 → 规则化 → 优化。
    禁止只理解不执行、只执行不验证、只完成不复盘。
    """
    rule_id = "L008"
    rule_name = "执行闭环铁律"
    severity = Severity.P1_BLOCKING
    category = RuleCategory.EXECUTION
    description = "检查是否完成了完整的执行闭环"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        steps_completed = context.get("execution_steps", [])
        required_steps = ["perceive", "understand", "plan", "execute", "verify"]

        missing = [s for s in required_steps if s not in steps_completed]
        if missing:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"执行闭环缺失步骤: {', '.join(missing)}",
                context={"completed": steps_completed, "missing": missing},
                action_taken="blocked",
                recovery_path="完整闭环: 感知 → 理解 → 规划 → 执行 → 验证 → 记录 → 复盘 → 规则化 → 优化"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details=f"缺失步骤: {missing}")

        return RuleResult(rule_id=self.rule_id, passed=True, details="执行闭环完整")


class L009_ResultOrientedRule(BaseRule):
    """
    铁律9: 结果导向铁律
    价值标准是"有没有推进"，不是"说得像不像"。
    """
    rule_id = "L009"
    rule_name = "结果导向铁律"
    severity = Severity.P2_WARNING
    category = RuleCategory.EXECUTION
    description = "检查输出是否产生了可衡量的推进成果"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        concrete_actions = context.get("concrete_actions", [])
        has_deliverable = context.get("has_deliverable", False)

        if not concrete_actions and not has_deliverable:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message="输出没有产生可衡量的推进成果",
                context={"response_type": context.get("response_type", "unknown")},
                action_taken="warned",
                recovery_path="产出: 可执行命令/明确修复点/规则草案/结构化框架/可迭代中间产物"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="无可衡量推进成果")

        return RuleResult(rule_id=self.rule_id, passed=True, details=f"产生 {len(concrete_actions)} 个具体行动")


class L010_ZeroHallucinationRule(BaseRule):
    """
    铁律10: 零幻觉铁律
    严禁：编造事实/状态/结果/数据/工具行为/文件内容。
    真实性永远高于流畅性。
    """
    rule_id = "L010"
    rule_name = "零幻觉铁律"
    severity = Severity.P0_CRITICAL
    category = RuleCategory.EXECUTION
    description = "检查输出中是否有未验证的事实声明"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        unverified_claims = context.get("unverified_claims", [])
        verified_sources = context.get("verified_sources", {})

        unverified = []
        for claim in unverified_claims:
            claim_key = hashlib.md5(claim.encode()).hexdigest()[:8]
            if claim_key not in verified_sources:
                unverified.append(claim)

        if unverified:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"输出包含 {len(unverified)} 条未验证声明",
                context={"unverified": unverified[:5]},  # 最多显示5条
                action_taken="blocked",
                recovery_path="所有事实必须来源可查: 工具验证 > 代码确认 > 文档引用 > 用户确认"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details=f"{len(unverified)} 条未验证声明")

        return RuleResult(rule_id=self.rule_id, passed=True, details="所有声明已验证")


class L011_SelfVerificationRule(BaseRule):
    """
    铁律11: 自我验证铁律
    输出前自检：目标对齐/理解歧义/逻辑自洽/满足要求/遗漏约束/未标记假设/可执行性。
    """
    rule_id = "L011"
    rule_name = "自我验证铁律"
    severity = Severity.P1_BLOCKING
    category = RuleCategory.EXECUTION
    description = "检查输出前是否进行了自我验证"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        self_checks = context.get("self_checks_performed", [])
        required_checks = ["goal_alignment", "logic_consistency", "constraint_satisfaction", "executability"]

        missing = [c for c in required_checks if c not in self_checks]
        if missing:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"自我验证缺失: {', '.join(missing)}",
                context={"performed": self_checks, "missing": missing},
                action_taken="warned",
                recovery_path="输出前自检: 目标对齐/理解歧义/逻辑自洽/满足要求/遗漏约束/未标记假设/可执行性"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details=f"缺失验证: {missing}")

        return RuleResult(rule_id=self.rule_id, passed=True, details="自我验证完整")


class L012_SelfCorrectionRule(BaseRule):
    """
    铁律12: 自我纠错铁律
    发现错误 → 定位 → 分类 → 修正结果 → 修正触发逻辑 → 补充约束 → 记录模式 → 防止重犯。
    必须修根因。
    """
    rule_id = "L012"
    rule_name = "自我纠错铁律"
    severity = Severity.P1_BLOCKING
    category = RuleCategory.EXECUTION
    description = "检查纠错是否修了根因而非表面"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        error_detected = context.get("error_detected", False)
        if not error_detected:
            return RuleResult(rule_id=self.rule_id, passed=True, details="无错误需要纠正")

        root_cause_identified = context.get("root_cause_identified", False)
        trigger_logic_fixed = context.get("trigger_logic_fixed", False)
        pattern_recorded = context.get("pattern_recorded", False)

        if not root_cause_identified:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message="错误修复未定位根因",
                context={"fix_type": context.get("fix_type", "unknown")},
                action_taken="blocked",
                recovery_path="必须修根因: 定位 → 分类 → 修正结果 → 修正触发逻辑 → 补充约束 → 记录模式 → 防止重犯"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="未修根因")

        if not trigger_logic_fixed:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message="纠错未修正触发逻辑",
                action_taken="warned",
                recovery_path="修正触发逻辑，防止同样错误再次发生"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="未修正触发逻辑")

        return RuleResult(rule_id=self.rule_id, passed=True, details="纠错完整：根因+触发逻辑+模式记录")


# ──────────────────────────────────────────────
# 第三层：规则治理 (L013-L019)
# ──────────────────────────────────────────────

class L013_ExperienceCaptureRule(BaseRule):
    """
    铁律13: 经验沉淀铁律
    沉淀：用户偏好/任务模式/高成功率路径/高失败率模式/有效约束/常用流程。
    禁止学过就忘、重复踩坑。
    """
    rule_id = "L013"
    rule_name = "经验沉淀铁律"
    severity = Severity.P2_WARNING
    category = RuleCategory.GOVERNANCE
    description = "检查完成任务后是否沉淀了可复用经验"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        task_complexity = context.get("task_complexity", 0)
        experience_saved = context.get("experience_saved", False)
        memory_entries_added = context.get("memory_entries_added", 0)

        # 复杂度 >= 5 的任务应该沉淀经验
        if task_complexity >= 5 and not experience_saved and memory_entries_added == 0:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"复杂任务 (复杂度={task_complexity}) 完成后未沉淀经验",
                context={"task_complexity": task_complexity},
                action_taken="warned",
                recovery_path="完成任务后保存: 用户偏好/任务模式/高成功率路径/高失败率模式/有效约束/常用流程"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="经验未沉淀")

        return RuleResult(rule_id=self.rule_id, passed=True, details=f"已沉淀 {memory_entries_added} 条经验")


class L014_RuleGenerationRule(BaseRule):
    """
    铁律14: 规则生成铁律
    高价值任务完成后判断是否形成新规则。
    """
    rule_id = "L014"
    rule_name = "规则生成铁律"
    severity = Severity.P2_WARNING
    category = RuleCategory.GOVERNANCE
    description = "检查是否识别了可以形成新规则的模式"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        new_pattern_discovered = context.get("new_pattern_discovered", False)
        rule_created = context.get("rule_created", False)

        if new_pattern_discovered and not rule_created:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message="发现新模式但未形成新规则",
                context={"pattern": context.get("pattern_description", "unknown")},
                action_taken="warned",
                recovery_path="高价值任务完成后检查: 是否可形成新规则（触发条件/适用场景/行为方式/约束/成功标准/失败信号）"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="新规则未创建")

        return RuleResult(rule_id=self.rule_id, passed=True, details="规则生成检查通过")


class L015_RulePriorityRule(BaseRule):
    """
    铁律15: 规则优先级铁律
    冲突时：1.真实性 2.安全性 3.用户真实目标 4.可执行性 5.稳定性 6.一致性 7.效率 8.表达质量。
    """
    rule_id = "L015"
    rule_name = "规则优先级铁律"
    severity = Severity.P0_CRITICAL
    category = RuleCategory.GOVERNANCE
    description = "检查规则冲突时是否按正确优先级裁决"

    PRIORITY_ORDER = [
        "authenticity",    # 1. 真实性
        "safety",          # 2. 安全性
        "user_goal",       # 3. 用户真实目标
        "executability",   # 4. 可执行性
        "stability",       # 5. 稳定性
        "consistency",     # 6. 一致性
        "efficiency",      # 7. 效率
        "expression",      # 8. 表达质量
    ]

    def check(self, context: Dict[str, Any]) -> RuleResult:
        conflict_detected = context.get("rule_conflict_detected", False)
        if not conflict_detected:
            return RuleResult(rule_id=self.rule_id, passed=True, details="无规则冲突")

        resolution = context.get("conflict_resolution", {})
        higher_priority = resolution.get("higher_priority_value", "")
        lower_priority = resolution.get("lower_priority_value", "")

        if higher_priority and lower_priority:
            high_idx = self.PRIORITY_ORDER.index(higher_priority) if higher_priority in self.PRIORITY_ORDER else 999
            low_idx = self.PRIORITY_ORDER.index(lower_priority) if lower_priority in self.PRIORITY_ORDER else 999

            if high_idx > low_idx:
                violation = RuleViolation(
                    rule_id=self.rule_id,
                    rule_name=self.rule_name,
                    severity=self.severity,
                    category=self.category,
                    message=f"规则优先级裁决错误: {higher_priority} 不应优先于 {lower_priority}",
                    context={"resolution": resolution},
                    action_taken="blocked",
                    recovery_path="优先级: 真实性 > 安全性 > 用户真实目标 > 可执行性 > 稳定性 > 一致性 > 效率 > 表达质量"
                )
                return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                                details="优先级裁决错误")

        return RuleResult(rule_id=self.rule_id, passed=True, details="优先级裁决正确")


class L016_RuleReuseRule(BaseRule):
    """
    铁律16: 规则复用铁律
    已证明有效的规则优先复用。禁止无意义重新发明。
    """
    rule_id = "L016"
    rule_name = "规则复用铁律"
    severity = Severity.P2_WARNING
    category = RuleCategory.GOVERNANCE
    description = "检查是否有可复用规则但选择了重新发明"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        existing_rules_checked = context.get("existing_rules_checked", False)
        reinvented = context.get("reinvented_solution", False)

        if reinvented and not existing_rules_checked:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message="重新发明已有解决方案，未检查现有规则",
                context={"reinvented": context.get("reinvented_description", "")},
                action_taken="warned",
                recovery_path="先搜索已有规则/Skill/记忆，确认无匹配再重新发明"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="未复用已有规则")

        return RuleResult(rule_id=self.rule_id, passed=True, details="规则复用检查通过")


class L017_RuleIterationRule(BaseRule):
    """
    铁律17: 规则迭代铁律
    持续评估：成功率/稳定性/适用边界/误伤率/冗余度。
    低质量规则：降权/修订/合并/拆分/废弃。
    """
    rule_id = "L017"
    rule_name = "规则迭代铁律"
    severity = Severity.P3_INFO
    category = RuleCategory.GOVERNANCE
    description = "检查是否定期评估和迭代规则质量"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        rules_evaluated = context.get("rules_evaluated", False)
        low_quality_rules = context.get("low_quality_rules_identified", [])

        if not rules_evaluated:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message="未进行规则质量评估",
                action_taken="warned",
                recovery_path="定期评估规则: 成功率/稳定性/适用边界/误伤率/冗余度"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="未评估规则质量")

        return RuleResult(rule_id=self.rule_id, passed=True,
                        details=f"评估完成，识别 {len(low_quality_rules)} 条低质量规则")


class L018_RuleDedupRule(BaseRule):
    """
    铁律18: 规则合并与去重铁律
    高度相似 → 合并。覆盖过大/内部冲突/场景差异 → 拆分。
    """
    rule_id = "L018"
    rule_name = "规则合并与去重铁律"
    severity = Severity.P3_INFO
    category = RuleCategory.GOVERNANCE
    description = "检查规则库中是否有重复或冲突的规则"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        duplicate_rules = context.get("duplicate_rules_found", [])
        conflicting_rules = context.get("conflicting_rules_found", [])

        if duplicate_rules or conflicting_rules:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"发现 {len(duplicate_rules)} 条重复规则, {len(conflicting_rules)} 条冲突规则",
                context={"duplicates": duplicate_rules[:3], "conflicts": conflicting_rules[:3]},
                action_taken="warned",
                recovery_path="高度相似→合并，覆盖过大/冲突/场景差异→拆分"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="规则需要去重/合并")

        return RuleResult(rule_id=self.rule_id, passed=True, details="规则库清晰无重复")


class L019_LongTermMemoryValueRule(BaseRule):
    """
    铁律19: 长期记忆价值铁律
    只记忆：持续影响判断/显著提高效率/降低错误率/可复用结构/用户长期偏好。
    记忆是武器库，不是堆积。
    """
    rule_id = "L019"
    rule_name = "长期记忆价值铁律"
    severity = Severity.P2_WARNING
    category = RuleCategory.GOVERNANCE
    description = "检查记忆条目是否符合长期价值标准"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        memory_entries = context.get("recent_memory_entries", [])
        low_value_entries = []

        for entry in memory_entries:
            content = entry.get("content", "")
            has_persistent_value = (
                len(content) > 10 and
                not entry.get("is_task_progress", False) and
                not entry.get("is_obvious", False) and
                entry.get("affects_future_judgment", False) or
                entry.get("reduces_error_rate", False) or
                entry.get("is_user_preference", False)
            )
            if not has_persistent_value:
                low_value_entries.append(entry)

        if low_value_entries:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"发现 {len(low_value_entries)} 条低价值记忆条目",
                context={"low_value_count": len(low_value_entries)},
                action_taken="warned",
                recovery_path="记忆标准: 持续影响判断/显著提高效率/降低错误率/可复用结构/用户长期偏好。禁止堆积临时状态。"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="低价值记忆条目过多")

        return RuleResult(rule_id=self.rule_id, passed=True, details="记忆质量合格")


# ──────────────────────────────────────────────
# 第四层：任务推进 (L020-L024)
# ──────────────────────────────────────────────

class L020_DecompositionRule(BaseRule):
    """
    铁律20: 拆解铁律
    复杂任务先拆解：目标/阶段/依赖/风险/优先级/交付物。
    禁止混沌式输出。
    """
    rule_id = "L020"
    rule_name = "拆解铁律"
    severity = Severity.P1_BLOCKING
    category = RuleCategory.TASK_PROGRESS
    description = "检查复杂任务是否经过结构化拆解"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        is_complex = context.get("is_complex_task", False)
        if not is_complex:
            return RuleResult(rule_id=self.rule_id, passed=True, details="非复杂任务，无需拆解")

        decomposition = context.get("decomposition", {})
        required = ["goal", "phases", "dependencies", "risks", "priorities", "deliverables"]
        missing = [k for k in required if k not in decomposition or not decomposition[k]]

        if missing:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"复杂任务拆解缺失: {', '.join(missing)}",
                context={"missing": missing},
                action_taken="blocked",
                recovery_path="复杂任务拆解: 目标/阶段/依赖/风险/优先级/交付物"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details=f"拆解缺失: {missing}")

        return RuleResult(rule_id=self.rule_id, passed=True, details="任务拆解完整")


class L021_MinimalProgressRule(BaseRule):
    """
    铁律21: 最小可推进成果铁律
    无法一次完成时，必须产出：可执行命令/明确修复点/规则草案/结构化框架/可迭代中间产物。
    """
    rule_id = "L021"
    rule_name = "最小可推进成果铁律"
    severity = Severity.P1_BLOCKING
    category = RuleCategory.TASK_PROGRESS
    description = "检查未完成的任务是否产出了可推进的中间成果"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        task_complete = context.get("task_complete", False)
        if task_complete:
            return RuleResult(rule_id=self.rule_id, passed=True, details="任务已完成")

        has_intermediate_deliverable = context.get("has_intermediate_deliverable", False)
        deliverable_type = context.get("deliverable_type", "")

        if not has_intermediate_deliverable:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message="任务未完成且无可推进的中间成果",
                action_taken="blocked",
                recovery_path="产出: 可执行命令/明确修复点/规则草案/结构化框架/可迭代中间产物"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="无可推进成果")

        return RuleResult(rule_id=self.rule_id, passed=True,
                        details=f"中间成果: {deliverable_type}")


class L022_ModularRule(BaseRule):
    """
    铁律22: 模块化铁律
    核心能力按模块：理解/上下文/记忆/规则/规划/执行/验证/复盘/进化。
    禁止能力无序堆叠。
    """
    rule_id = "L022"
    rule_name = "模块化铁律"
    severity = Severity.P2_WARNING
    category = RuleCategory.TASK_PROGRESS
    description = "检查输出/代码是否遵循模块化结构"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        module_structure = context.get("module_structure", {})
        if not module_structure:
            return RuleResult(rule_id=self.rule_id, passed=True, details="不涉及模块化检查")

        well_structured = all(
            isinstance(v, dict) for v in module_structure.values()
        )

        if not well_structured:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message="模块结构混乱，存在无序堆叠",
                context={"module_structure": {k: type(v).__name__ for k, v in module_structure.items()}},
                action_taken="warned",
                recovery_path="核心能力模块化: 理解/上下文/记忆/规则/规划/执行/验证/复盘/进化"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="模块结构混乱")

        return RuleResult(rule_id=self.rule_id, passed=True, details="模块化结构良好")


class L023_ToolFirstRule(BaseRule):
    """
    铁律23: 工具优先铁律
    能查就查/能算就算/能读就读/能执行就执行/能验证就验证。
    有工具不用只靠猜 → 禁止。
    """
    rule_id = "L023"
    rule_name = "工具优先铁律"
    severity = Severity.P0_CRITICAL
    category = RuleCategory.TASK_PROGRESS
    description = "检查是否在有可用工具的情况下靠猜测回答"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        guessed_when_tool_available = context.get("guessed_when_tool_available", False)
        tool_used = context.get("tool_used", False)
        answerable_by_tool = context.get("answerable_by_tool", False)

        if answerable_by_tool and not tool_used and guessed_when_tool_available:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message="有可用工具但选择了猜测",
                context={"guessed_answer": context.get("guessed_answer", "")},
                action_taken="blocked",
                recovery_path="能查就查/能算就算/能读就读/能执行就执行/能验证就验证。禁止有工具却靠猜。"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="未使用可用工具")

        return RuleResult(rule_id=self.rule_id, passed=True, details="工具优先原则遵守")


class L024_TrackableStateRule(BaseRule):
    """
    铁律24: 状态可追踪铁律
    明确：当前目标/状态/已完成/未完成/阻塞点/下一步/采用规则。
    让任务可追踪、可恢复、可继续。
    """
    rule_id = "L024"
    rule_name = "状态可追踪铁律"
    severity = Severity.P1_BLOCKING
    category = RuleCategory.TASK_PROGRESS
    description = "检查任务状态是否可追踪和恢复"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        state = context.get("task_state", {})
        required = ["current_goal", "status", "completed", "remaining", "next_step"]
        missing = [k for k in required if k not in state or not state[k]]

        if missing:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"任务状态不可追踪，缺失: {', '.join(missing)}",
                context={"state": state, "missing": missing},
                action_taken="warned",
                recovery_path="状态追踪: 当前目标/状态/已完成/未完成/阻塞点/下一步/采用规则"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details=f"状态缺失: {missing}")

        return RuleResult(rule_id=self.rule_id, passed=True, details="状态可追踪")


# ──────────────────────────────────────────────
# 第五层：进化与治理 (L025-L034)
# ──────────────────────────────────────────────

class L025_ReviewRule(BaseRule):
    """
    铁律25: 复盘铁律
    重要任务后复盘：目标是否达成/理解哪里脆弱/执行哪里易失败/哪个规则最有效/如何转化未来优势。
    """
    rule_id = "L025"
    rule_name = "复盘铁律"
    severity = Severity.P2_WARNING
    category = RuleCategory.EVOLUTION
    description = "检查重要任务后是否进行了复盘"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        is_important_task = context.get("is_important_task", False)
        if not is_important_task:
            return RuleResult(rule_id=self.rule_id, passed=True, details="非重要任务，无需复盘")

        review_completed = context.get("review_completed", False)
        review_items = context.get("review_items", [])
        required_items = ["goal_achieved", "understanding_weaknesses", "execution_risks",
                         "effective_rules", "future_improvements"]

        if not review_completed:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"重要任务未完成复盘 (已覆盖 {len(review_items)}/{len(required_items)} 项)",
                context={"review_items": review_items},
                action_taken="warned",
                recovery_path="复盘: 目标是否达成/理解哪里脆弱/执行哪里易失败/哪个规则最有效/如何转化未来优势"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="复盘未完成")

        return RuleResult(rule_id=self.rule_id, passed=True, details="复盘完整")


class L026_ProactiveOptimizationRule(BaseRule):
    """
    铁律26: 主动优化铁律
    主动发现：重复动作/冗余流程/低效表达/常见歧义/规则空白/可自动化节点/可规避错误。
    """
    rule_id = "L026"
    rule_name = "主动优化铁律"
    severity = Severity.P2_WARNING
    category = RuleCategory.EVOLUTION
    description = "检查是否主动识别了可优化的节点"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        optimizations_found = context.get("optimizations_found", [])
        repeated_patterns = context.get("repeated_patterns_detected", False)

        if repeated_patterns and not optimizations_found:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message="检测到重复模式但未主动优化",
                action_taken="warned",
                recovery_path="主动发现: 重复动作/冗余流程/低效表达/常见歧义/规则空白/可自动化节点/可规避错误"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="未主动优化重复模式")

        return RuleResult(rule_id=self.rule_id, passed=True,
                        details=f"主动优化识别 {len(optimizations_found)} 个改进点")


class L027_ConsistencyRule(BaseRule):
    """
    铁律27: 一致性铁律
    同类问题保持：判断标准/输出结构/规则调用/质量标准/错误处理一致。
    """
    rule_id = "L027"
    rule_name = "一致性铁律"
    severity = Severity.P2_WARNING
    category = RuleCategory.EVOLUTION
    description = "检查同类任务的输出一致性"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        previous_outputs = context.get("previous_outputs_for_same_task_type", [])
        current_output = context.get("current_output_structure", "")

        if not previous_outputs:
            return RuleResult(rule_id=self.rule_id, passed=True, details="无历史输出可比较")

        consistency_score = context.get("output_consistency_score", 1.0)

        if consistency_score < 0.6:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"同类任务输出一致性低 (score={consistency_score:.2f})",
                action_taken="warned",
                recovery_path="同类问题保持判断标准/输出结构/规则调用/质量标准/错误处理一致"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details=f"一致性得分过低: {consistency_score:.2f}")

        return RuleResult(rule_id=self.rule_id, passed=True,
                        details=f"一致性良好 (score={consistency_score:.2f})")


class L028_StabilityOverShowoffRule(BaseRule):
    """
    铁律28: 稳定性高于炫技铁律
    进化目标：越来越稳、越来越强、越来越可控。
    复杂不等于高级。稳定且强才是方向。
    """
    rule_id = "L028"
    rule_name = "稳定性高于炫技铁律"
    severity = Severity.P2_WARNING
    category = RuleCategory.EVOLUTION
    description = "检查是否选择了过于复杂但不必要的方案"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        complexity_score = context.get("solution_complexity", 0)
        simpler_alternative_exists = context.get("simpler_alternative_exists", False)

        if complexity_score > 7 and simpler_alternative_exists:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"选择了高复杂度方案 (score={complexity_score}) 但存在更简方案",
                action_taken="warned",
                recovery_path="稳定且强才是方向。复杂≠高级。优先选择简单可靠的方案。"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="方案过于复杂")

        return RuleResult(rule_id=self.rule_id, passed=True, details="方案复杂度合理")


class L029_BoundaryClarityRule(BaseRule):
    """
    铁律29: 边界清晰铁律
    必须知道：知道什么/不知道什么/能做什么/不能做什么/哪些是事实/哪些是推测/哪些已验证/哪些未验证。
    """
    rule_id = "L029"
    rule_name = "边界清晰铁律"
    severity = Severity.P1_BLOCKING
    category = RuleCategory.EVOLUTION
    description = "检查输出是否明确区分了已知/未知/推测/已验证"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        boundaries = context.get("boundaries_declared", {})
        required = ["known", "unknown", "can_do", "cannot_do", "verified", "unverified"]
        missing = [k for k in required if k not in boundaries]

        if missing:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"边界声明不完整，缺失: {', '.join(missing)}",
                context={"boundaries": boundaries},
                action_taken="warned",
                recovery_path="明确声明: 知道什么/不知道什么/能做什么/不能做什么/已验证/未验证"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details=f"边界缺失: {missing}")

        return RuleResult(rule_id=self.rule_id, passed=True, details="边界清晰")


class L030_SelfRefactorRule(BaseRule):
    """
    铁律30: 自我重构铁律
    旧规则阻碍效率时允许重构，但须：有明确问题证据/有替代方案/不破坏核心原则/有升级记录/有前后差异说明。
    """
    rule_id = "L030"
    rule_name = "自我重构铁律"
    severity = Severity.P1_BLOCKING
    category = RuleCategory.EVOLUTION
    description = "检查规则重构是否符合安全条件"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        is_refactor = context.get("is_rule_refactor", False)
        if not is_refactor:
            return RuleResult(rule_id=self.rule_id, passed=True, details="不涉及规则重构")

        conditions = {
            "problem_evidence": context.get("problem_evidence", False),
            "alternative_plan": context.get("alternative_plan", False),
            "core_principles_preserved": context.get("core_principles_preserved", True),
            "upgrade_log": context.get("upgrade_log", False),
            "before_after_diff": context.get("before_after_diff", False),
        }

        failed = [k for k, v in conditions.items() if not v]
        if failed:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"规则重构条件不满足: {', '.join(failed)}",
                context={"conditions": conditions},
                action_taken="blocked",
                recovery_path="重构须满足: 明确问题证据/替代方案/不破坏核心原则/升级记录/前后差异说明"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details=f"重构条件缺失: {failed}")

        return RuleResult(rule_id=self.rule_id, passed=True, details="重构条件全部满足")


class L031_StructuredOutputRule(BaseRule):
    """
    铁律31: 输出结构化铁律
    复杂任务输出包含：目标/当前判断/关键依据/主要问题/下一步/可沉淀规则/风险与边界。
    """
    rule_id = "L031"
    rule_name = "输出结构化铁律"
    severity = Severity.P2_WARNING
    category = RuleCategory.EVOLUTION
    description = "检查复杂任务输出是否结构化"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        is_complex = context.get("is_complex_task", False)
        if not is_complex:
            return RuleResult(rule_id=self.rule_id, passed=True, details="非复杂任务")

        output_structure = context.get("output_structure", {})
        required = ["goal", "current_judgment", "key_evidence", "main_issues",
                    "next_steps", "rules_to_capture", "risks_and_boundaries"]
        missing = [k for k in required if k not in output_structure]

        if missing:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"复杂任务输出结构不完整，缺失: {', '.join(missing)}",
                context={"missing_sections": missing},
                action_taken="warned",
                recovery_path="输出结构: 目标/当前判断/关键依据/主要问题/下一步/可沉淀规则/风险与边界"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details=f"输出缺失: {missing}")

        return RuleResult(rule_id=self.rule_id, passed=True, details="输出结构完整")


class L032_EvolutionDefinitionRule(BaseRule):
    """
    铁律32: 自我进化定义铁律
    进化体现：理解更深/歧义更少/错误更少/规则更清晰/决策更稳/推进更强/复用更高/长期一致性更好。
    """
    rule_id = "L032"
    rule_name = "自我进化定义铁律"
    severity = Severity.P3_INFO
    category = RuleCategory.EVOLUTION
    description = "检查系统是否在进化指标上有正向变化"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        evolution_metrics = context.get("evolution_metrics", {})
        if not evolution_metrics:
            return RuleResult(rule_id=self.rule_id, passed=True, details="无进化指标数据")

        negative_trends = []
        for metric, value in evolution_metrics.items():
            if isinstance(value, (int, float)) and value < 0:
                negative_trends.append(metric)

        if negative_trends:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"进化指标负向变化: {', '.join(negative_trends)}",
                context={"evolution_metrics": evolution_metrics},
                action_taken="warned",
                recovery_path="进化指标: 理解更深/歧义更少/错误更少/规则更清晰/决策更稳/推进更强/复用更高/长期一致性更好"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details=f"负向指标: {negative_trends}")

        return RuleResult(rule_id=self.rule_id, passed=True, details="进化指标正向")


class L033_UltimateMissionRule(BaseRule):
    """
    铁律33: 终极使命铁律
    Hermes 追求长期正确、长期稳定、长期进化。
    """
    rule_id = "L033"
    rule_name = "终极使命铁律"
    severity = Severity.P1_BLOCKING
    category = RuleCategory.EVOLUTION
    description = "检查决策是否符合长期正确/稳定/进化方向"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        decision = context.get("decision_description", "")
        long_term_beneficial = context.get("long_term_beneficial", True)

        if not long_term_beneficial:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message="决策不利于长期正确/稳定/进化",
                context={"decision": decision},
                action_taken="warned",
                recovery_path="Hermes 追求长期正确、长期稳定、长期进化。每个决策都问：这对长期好吗？"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details="不符合长期使命")

        return RuleResult(rule_id=self.rule_id, passed=True, details="符合长期使命")


class L034_SupremeArbitrationRule(BaseRule):
    """
    铁律34: 最高裁决铁律
    不真实/不清晰/不可执行/不可验证/不可复用/不利于沉淀规则/不利于优化/不利于推进 → 低质量输出。
    """
    rule_id = "L034"
    rule_name = "最高裁决铁律"
    severity = Severity.P0_CRITICAL
    category = RuleCategory.EVOLUTION
    description = "最终质量裁决：检查输出是否满足最低质量标准"

    def check(self, context: Dict[str, Any]) -> RuleResult:
        output = context.get("output", "")
        quality_checks = {
            "authentic": context.get("output_is_authentic", True),
            "clear": context.get("output_is_clear", True),
            "executable": context.get("output_is_executable", True),
            "verifiable": context.get("output_is_verifiable", True),
            "reusable": context.get("output_is_reusable", True),
            "contributes_to_rules": context.get("contributes_to_rules", True),
            "supports_optimization": context.get("supports_optimization", True),
            "advances_progress": context.get("advances_progress", True),
        }

        failed = [k for k, v in quality_checks.items() if not v]
        if failed:
            violation = RuleViolation(
                rule_id=self.rule_id,
                rule_name=self.rule_name,
                severity=self.severity,
                category=self.category,
                message=f"输出质量不达标，失败项: {', '.join(failed)}",
                context={"quality_checks": quality_checks},
                action_taken="blocked",
                recovery_path="输出必须: 真实/清晰/可执行/可验证/可复用/有利于沉淀规则/有利于优化/有利于推进"
            )
            return RuleResult(rule_id=self.rule_id, passed=False, violation=violation,
                            details=f"质量失败: {failed}")

        return RuleResult(rule_id=self.rule_id, passed=True, details="输出质量合格")





# ──────────────────────────────────────────────
# P0 规则引擎 (Rule Engine)
# ──────────────────────────────────────────────

class P0RuleEngine:
    """
    P0 铁律规则引擎。

    用法:
        engine = P0RuleEngine()
        engine.register_all()

        # 检查输出
        result = engine.evaluate({
            "user_input": "帮我优化策略",
            "response": "...",
            "has_decomposition": True,
            ...
        })

        # 获取违规记录
        for violation in result.violations:
            logger.warning(f"[{violation.rule_id}] {violation.message}")
    """

    def __init__(self):
        self.rules: Dict[str, BaseRule] = {}
        self.violation_log: List[RuleViolation] = []
        self.stats: Dict[str, int] = {
            "total_checks": 0,
            "total_violations": 0,
            "blocked": 0,
            "warned": 0,
            "info": 0,
        }

    def register(self, rule: BaseRule):
        """注册一条规则"""
        self.rules[rule.rule_id] = rule
        logger.info(f"P0RuleEngine: registered {rule.rule_id} - {rule.rule_name}")

    def register_all(self):
        """注册全部 34 条铁律"""
        rule_classes = [
            # 第一层：理解与决策
            L001_GoalFirstRule,
            L002_DeepUnderstandingRule,
            L003_StructuredParsingRule,
            L004_UncertaintyExplicitRule,
            L005_MultiIntentRule,
            L006_ContextBindingRule,
            L007_GoalAlignmentRule,
            # 第二层：执行与验证
            L008_ExecutionLoopRule,
            L009_ResultOrientedRule,
            L010_ZeroHallucinationRule,
            L011_SelfVerificationRule,
            L012_SelfCorrectionRule,
            # 第三层：规则治理
            L013_ExperienceCaptureRule,
            L014_RuleGenerationRule,
            L015_RulePriorityRule,
            L016_RuleReuseRule,
            L017_RuleIterationRule,
            L018_RuleDedupRule,
            L019_LongTermMemoryValueRule,
            # 第四层：任务推进
            L020_DecompositionRule,
            L021_MinimalProgressRule,
            L022_ModularRule,
            L023_ToolFirstRule,
            L024_TrackableStateRule,
            # 第五层：进化与治理
            L025_ReviewRule,
            L026_ProactiveOptimizationRule,
            L027_ConsistencyRule,
            L028_StabilityOverShowoffRule,
            L029_BoundaryClarityRule,
            L030_SelfRefactorRule,
            L031_StructuredOutputRule,
            L032_EvolutionDefinitionRule,
            L033_UltimateMissionRule,
            L034_SupremeArbitrationRule,
        ]

        for rule_cls in rule_classes:
            self.register(rule_cls())

    def enable(self, rule_id: str):
        """启用指定规则"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = True
            logger.info(f"P0RuleEngine: enabled {rule_id}")

    def disable(self, rule_id: str):
        """禁用指定规则"""
        if rule_id in self.rules:
            self.rules[rule_id].enabled = False
            logger.info(f"P0RuleEngine: disabled {rule_id}")

    def enable_category(self, category: RuleCategory):
        """启用某分类的全部规则"""
        count = 0
        for rule in self.rules.values():
            if rule.category == category:
                rule.enabled = True
                count += 1
        logger.info(f"P0RuleEngine: enabled {count} rules in category {category.value}")

    def disable_category(self, category: RuleCategory):
        """禁用某分类的全部规则"""
        count = 0
        for rule in self.rules.values():
            if rule.category == category:
                rule.enabled = False
                count += 1
        logger.info(f"P0RuleEngine: disabled {count} rules in category {category.value}")

    def evaluate(self, context: Dict[str, Any]) -> "EvaluationResult":
        """
        对上下文执行全部启用的规则检查。

        返回:
            EvaluationResult 包含通过/失败的规则和所有违规记录
        """
        self.stats["total_checks"] += 1
        results: List[RuleResult] = []
        violations: List[RuleViolation] = []
        blocked_rules: List[str] = []
        warned_rules: List[str] = []

        for rule_id in sorted(self.rules.keys()):
            rule = self.rules[rule_id]
            if not rule.enabled:
                continue

            result = rule.check(context)
            results.append(result)

            if not result.passed and result.violation:
                violations.append(result.violation)
                self.stats["total_violations"] += 1
                self.violation_log.append(result.violation)

                action = result.violation.action_taken
                if action == "blocked":
                    blocked_rules.append(rule_id)
                    self.stats["blocked"] += 1
                elif action == "warned":
                    warned_rules.append(rule_id)
                    self.stats["warned"] += 1
                else:
                    self.stats["info"] += 1

        return EvaluationResult(
            total_rules=len([r for r in self.rules.values() if r.enabled]),
            passed=len(results) - len(violations),
            failed=len(violations),
            blocked=blocked_rules,
            warned=warned_rules,
            violations=violations,
            results=results,
        )

    def get_violation_summary(self, limit: int = 20) -> str:
        """获取违规记录摘要"""
        if not self.violation_log:
            return "P0铁律: 无违规记录 ✅"

        lines = [f"P0铁律违规记录 (最近 {len(self.violation_log)} 条):"]
        for v in self.violation_log[-limit:]:
            ts = datetime.fromtimestamp(v.timestamp).strftime("%H:%M:%S")
            lines.append(f"  [{ts}] {v.rule_id} ({v.severity.value}) {v.rule_name}: {v.message}")
            if v.recovery_path:
                lines.append(f"          → {v.recovery_path}")

        return "\n".join(lines)

    def get_stats(self) -> Dict[str, Any]:
        """获取引擎统计信息"""
        return {
            **self.stats,
            "active_rules": len([r for r in self.rules.values() if r.enabled]),
            "total_rules": len(self.rules),
            "violation_rate": self.stats["total_violations"] / max(1, self.stats["total_checks"]),
        }


@dataclass
class EvaluationResult:
    """规则评估结果"""
    total_rules: int
    passed: int
    failed: int
    blocked: List[str]
    warned: List[str]
    violations: List[RuleViolation]
    results: List[RuleResult]

    @property
    def is_clean(self) -> bool:
        """是否完全没有违规"""
        return len(self.violations) == 0

    @property
    def is_blocked(self) -> bool:
        """是否有 P0 级别的阻断"""
        return len(self.blocked) > 0

    def summary(self) -> str:
        """生成人类可读的摘要"""
        status = "✅ PASS" if self.is_clean else f"❌ FAIL ({self.failed} violations)"
        parts = [f"P0 Iron Laws Check: {status}"]

        if self.blocked:
            parts.append(f"  BLOCKED rules: {', '.join(self.blocked)}")
        if self.warned:
            parts.append(f"  WARNING rules: {', '.join(self.warned)}")

        parts.append(f"  Score: {self.passed}/{self.total_rules} passed")
        return "\n".join(parts)


# ──────────────────────────────────────────────
# 便捷函数
# ──────────────────────────────────────────────

# 全局单例
_global_engine: Optional[P0RuleEngine] = None


def get_engine() -> P0RuleEngine:
    """获取全局 P0 规则引擎实例"""
    global _global_engine
    if _global_engine is None:
        _global_engine = P0RuleEngine()
        _global_engine.register_all()
    return _global_engine


def check_iron_laws(context: Dict[str, Any]) -> EvaluationResult:
    """
    便捷函数：对上下文执行 P0 铁律检查。

    用法:
        result = check_iron_laws({
            "user_input": "帮我写代码",
            "response": "...",
            "has_decomposition": True,
            "tool_used": True,
            ...
        })
        print(result.summary())
    """
    engine = get_engine()
    return engine.evaluate(context)


def check_and_block(context: Dict[str, Any]) -> Optional[str]:
    """
    检查并返回阻断信息（如果有）。
    如果有 P0 阻断规则，返回阻断消息；否则返回 None。
    """
    result = check_iron_laws(context)
    if result.is_blocked:
        blocked_messages = []
        for v in result.violations:
            if v.action_taken == "blocked":
                blocked_messages.append(f"[{v.rule_id}] {v.message}: {v.recovery_path}")
        return "P0铁律阻断:\n" + "\n".join(blocked_messages)
    return None
