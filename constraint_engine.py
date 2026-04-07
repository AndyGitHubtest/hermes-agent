"""
约束执行引擎 (Constraint Enforcement Engine)

10 大约束 + 5 大核心原则的完整代码实现。
所有约束必须通过，否则拒绝执行。

架构:
  User Input → InputConstraint → TaskParser → ExecutionConstraint
    → EvidenceConstraint → AntiHallucinationConstraint → AntiDriftConstraint
    → ValidationConstraint → ErrorConstraint → StateConstraint
    → OutputConstraint → RefusalMechanism → Output

每个约束都是独立的检查器，可组合使用。
"""

import logging
import time
import hashlib
from typing import Any, Dict, List, Optional
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("ConstraintEngine")


# ──────────────────────────────────────────────
# 数据结构
# ──────────────────────────────────────────────

class ConstraintStatus(Enum):
    PASSED = "PASSED"
    FAILED = "FAILED"
    SKIPPED = "SKIPPED"


class ExecutionPhase(Enum):
    INPUT = "input"
    PLANNING = "planning"
    EXECUTION = "execution"
    VALIDATION = "validation"
    OUTPUT = "output"


@dataclass
class ConstraintCheck:
    """单个约束检查结果"""
    constraint_name: str
    status: ConstraintStatus
    details: str
    blocking: bool = False
    recovery_action: str = ""
    timestamp: float = field(default_factory=time.time)


@dataclass
class TaskState:
    """任务状态记录（状态约束）"""
    task_id: str
    original_goal: str
    current_phase: ExecutionPhase = ExecutionPhase.INPUT
    completed_steps: List[str] = field(default_factory=list)
    results: Dict[str, Any] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    is_completed: bool = False
    is_blocked: bool = False
    block_reason: str = ""


@dataclass
class ExecutionRecord:
    """执行记录（证据约束）"""
    task_id: str
    data_source: str = ""
    execution_steps: List[str] = field(default_factory=list)
    raw_results: Dict[str, Any] = field(default_factory=dict)
    validation_results: Dict[str, bool] = field(default_factory=dict)
    has_evidence: bool = False
    evidence_chain: List[str] = field(default_factory=list)


# ──────────────────────────────────────────────
# 10 大约束检查器
# ──────────────────────────────────────────────

class InputConstraint:
    """
    1️⃣ 输入约束
    必须明确：目标 / 数据来源 / 成功标准
    不满足 → 拒绝执行
    """
    name = "输入约束"

    def check(self, context: Dict[str, Any]) -> ConstraintCheck:
        goal = context.get("task_goal", "")
        data_source = context.get("data_source", "")
        success_criteria = context.get("success_criteria", "")

        missing = []
        if not goal:
            missing.append("目标 (Goal)")
        if not data_source:
            missing.append("数据来源 (Data Source)")
        if not success_criteria:
            missing.append("成功标准 (Success Criteria)")

        if missing:
            return ConstraintCheck(
                constraint_name=self.name,
                status=ConstraintStatus.FAILED,
                blocking=True,
                details=f"输入约束不满足，缺失: {', '.join(missing)}",
                recovery_action="拒绝执行，要求用户补充: " + ", ".join(missing)
            )

        return ConstraintCheck(
            constraint_name=self.name,
            status=ConstraintStatus.PASSED,
            details=f"输入完整: 目标={goal[:50]}..., 来源={data_source}"
        )


class ExecutionConstraint:
    """
    2️⃣ 执行约束
    强制流程: 解析→计划→执行→获取结果→验证→输出
    禁止: 直接回答 / 跳过执行 / 跳过验证
    """
    name = "执行约束"
    REQUIRED_STEPS = ["parsed", "planned", "executed", "results_captured", "validated"]

    def check(self, context: Dict[str, Any]) -> ConstraintCheck:
        completed_steps = context.get("execution_steps", [])
        skipped_steps = context.get("skipped_steps", [])

        if skipped_steps:
            return ConstraintCheck(
                constraint_name=self.name,
                status=ConstraintStatus.FAILED,
                blocking=True,
                details=f"禁止跳过执行步骤: {', '.join(skipped_steps)}",
                recovery_action="必须完成所有步骤: 解析→计划→执行→获取结果→验证→输出"
            )

        missing = [s for s in self.REQUIRED_STEPS if s not in completed_steps]
        if missing:
            return ConstraintCheck(
                constraint_name=self.name,
                status=ConstraintStatus.FAILED,
                blocking=True,
                details=f"执行流程不完整，缺失: {', '.join(missing)}",
                recovery_action="继续完成缺失的执行步骤"
            )

        return ConstraintCheck(
            constraint_name=self.name,
            status=ConstraintStatus.PASSED,
            details=f"执行流程完整 ({len(completed_steps)}/{len(self.REQUIRED_STEPS)} 步)"
        )


class EvidenceConstraint:
    """
    3️⃣ 证据约束
    所有输出必须包含: [数据来源] / [执行过程] / [原始结果]
    否则 → 输出无效
    """
    name = "证据约束"

    def check(self, context: Dict[str, Any]) -> ConstraintCheck:
        has_data_source = context.get("has_data_source", False)
        has_execution_process = context.get("has_execution_process", False)
        has_raw_results = context.get("has_raw_results", False)

        missing = []
        if not has_data_source:
            missing.append("数据来源")
        if not has_execution_process:
            missing.append("执行过程")
        if not has_raw_results:
            missing.append("原始结果")

        if missing:
            return ConstraintCheck(
                constraint_name=self.name,
                status=ConstraintStatus.FAILED,
                blocking=True,
                details=f"证据链不完整，缺失: {', '.join(missing)}",
                recovery_action="补充: 数据来源 → 执行过程 → 原始结果"
            )

        return ConstraintCheck(
            constraint_name=self.name,
            status=ConstraintStatus.PASSED,
            details="证据链完整: 数据来源 ✓ 执行过程 ✓ 原始结果 ✓"
        )


class AntiHallucinationConstraint:
    """
    4️⃣ 幻觉约束
    禁止: 推测 / 补全未知 / 编造
    允许: 不知道 / 无法确认
    """
    name = "幻觉约束"
    SPECULATION_KEYWORDS = [
        "应该是", "一般来说", "可能是", "大概率", "通常情况下",
        "据我所知", "根据经验", "通常是", "往往是", "应该是这样的",
        "我认为是", "感觉是", "看起来是", "似乎", "可能", "大概",
        "也许", "应该没问题", "应该可以",
        "should be", "generally", "probably", "typically", "might be",
    ]

    def check(self, context: Dict[str, Any]) -> ConstraintCheck:
        response = context.get("response", "")
        unverified_claims = context.get("unverified_claims", [])
        has_fabrication = context.get("has_fabrication", False)
        has_speculation = False
        found_keywords = []

        for kw in self.SPECULATION_KEYWORDS:
            if kw.lower() in response.lower():
                has_speculation = True
                found_keywords.append(kw)

        if has_fabrication:
            return ConstraintCheck(
                constraint_name=self.name,
                status=ConstraintStatus.FAILED,
                blocking=True,
                details="检测到编造内容（无来源声明/虚构数据/伪造结果）",
                recovery_action="禁止编造。无法确认时输出: ❌ 无法确认（缺少数据/执行）"
            )

        if has_speculation:
            return ConstraintCheck(
                constraint_name=self.name,
                status=ConstraintStatus.FAILED,
                blocking=True,
                details=f"检测到推测性语言: {', '.join(found_keywords[:5])}",
                recovery_action="用'不知道'/'无法确认'替代推测，或补充执行验证"
            )

        if unverified_claims:
            return ConstraintCheck(
                constraint_name=self.name,
                status=ConstraintStatus.FAILED,
                blocking=True,
                details=f"存在 {len(unverified_claims)} 条未验证声明",
                recovery_action="验证所有声明或标记为未确认"
            )

        return ConstraintCheck(
            constraint_name=self.name,
            status=ConstraintStatus.PASSED,
            details="无幻觉检测通过（无编造/推测/未验证声明）"
        )


class AntiDriftConstraint:
    """
    5️⃣ 跑偏约束
    每一步检查: 当前步骤是否仍服务于原始目标？
    不满足 → 立即回滚
    """
    name = "跑偏约束"

    def check(self, context: Dict[str, Any]) -> ConstraintCheck:
        original_goal = context.get("original_goal", "")
        current_step_goal = context.get("current_step_goal", "")
        serves_original_goal = context.get("serves_original_goal", True)
        deviation_detected = context.get("deviation_detected", False)

        if deviation_detected or not serves_original_goal:
            return ConstraintCheck(
                constraint_name=self.name,
                status=ConstraintStatus.FAILED,
                blocking=True,
                details=f"检测到目标跑偏。原始目标: {original_goal[:50]}...，当前步骤: {current_step_goal[:50]}...",
                recovery_action="立即回滚到服务于原始目标的步骤"
            )

        return ConstraintCheck(
            constraint_name=self.name,
            status=ConstraintStatus.PASSED,
            details="目标对齐检查通过（当前步骤服务于原始目标）"
        )


class ValidationConstraint:
    """
    6️⃣ 验证约束
    所有关键结果必须: 可复现 / 可验证 / 可回溯
    """
    name = "验证约束"

    def check(self, context: Dict[str, Any]) -> ConstraintCheck:
        has_validation = context.get("has_validation", False)
        is_reproducible = context.get("is_reproducible", False)
        validation_method = context.get("validation_method", "")

        if not has_validation:
            return ConstraintCheck(
                constraint_name=self.name,
                status=ConstraintStatus.FAILED,
                blocking=True,
                details="关键结果未经验证",
                recovery_action="必须验证: 重新执行/数据对比/边界检查"
            )

        if not is_reproducible:
            return ConstraintCheck(
                constraint_name=self.name,
                status=ConstraintStatus.FAILED,
                blocking=True,
                details="结果不可复现",
                recovery_action="重新执行以确保结果可复现"
            )

        return ConstraintCheck(
            constraint_name=self.name,
            status=ConstraintStatus.PASSED,
            details=f"验证通过（方法: {validation_method or '自动'}，可复现: ✓）"
        )


class ErrorConstraint:
    """
    7️⃣ 错误约束
    出现错误 → 立即停止 → 输出错误 → 禁止继续
    """
    name = "错误约束"

    def check(self, context: Dict[str, Any]) -> ConstraintCheck:
        has_error = context.get("has_error", False)
        error_message = context.get("error_message", "")
        continued_after_error = context.get("continued_after_error", False)

        if has_error and continued_after_error:
            return ConstraintCheck(
                constraint_name=self.name,
                status=ConstraintStatus.FAILED,
                blocking=True,
                details=f"发生错误后继续执行: {error_message}",
                recovery_action="错误必须立即停止流程，禁止带错误继续执行"
            )

        if has_error:
            return ConstraintCheck(
                constraint_name=self.name,
                status=ConstraintStatus.FAILED,
                blocking=True,
                details=f"执行错误: {error_message}",
                recovery_action="输出错误详情，停止流程，等待用户指示"
            )

        return ConstraintCheck(
            constraint_name=self.name,
            status=ConstraintStatus.PASSED,
            details="无错误"
        )


class StateConstraint:
    """
    8️⃣ 状态约束
    必须记录: 当前任务阶段 / 已执行步骤 / 结果
    """
    name = "状态约束"

    def check(self, context: Dict[str, Any]) -> ConstraintCheck:
        task_state = context.get("task_state", {})
        has_current_phase = "current_phase" in task_state
        has_completed_steps = "completed_steps" in task_state
        has_results = "results" in task_state

        missing = []
        if not has_current_phase:
            missing.append("当前任务阶段")
        if not has_completed_steps:
            missing.append("已执行步骤")
        if not has_results:
            missing.append("执行结果")

        if missing:
            return ConstraintCheck(
                constraint_name=self.name,
                status=ConstraintStatus.FAILED,
                blocking=False,
                details=f"状态记录不完整，缺失: {', '.join(missing)}",
                recovery_action="记录状态以确保系统可恢复"
            )

        return ConstraintCheck(
            constraint_name=self.name,
            status=ConstraintStatus.PASSED,
            details=f"状态完整 (阶段={task_state.get('current_phase', '?')}, 步骤={len(task_state.get('completed_steps', []))})"
        )


class OutputConstraint:
    """
    9️⃣ 输出约束
    标准结构: [任务] / [执行] / [验证] / [结果] / [结论]
    禁止: 纯解释 / 无证据结论
    """
    name = "输出约束"
    REQUIRED_SECTIONS = ["任务", "执行", "验证", "结果", "结论"]

    def check(self, context: Dict[str, Any]) -> ConstraintCheck:
        output_structure = context.get("output_structure", {})
        is_explanation_only = context.get("is_explanation_only", False)
        has_unsupported_conclusion = context.get("has_unsupported_conclusion", False)

        if is_explanation_only:
            return ConstraintCheck(
                constraint_name=self.name,
                status=ConstraintStatus.FAILED,
                blocking=True,
                details="输出为纯解释性内容，无执行/验证/结果",
                recovery_action="必须包含执行结果和数据证明"
            )

        if has_unsupported_conclusion:
            return ConstraintCheck(
                constraint_name=self.name,
                status=ConstraintStatus.FAILED,
                blocking=True,
                details="结论无证据支持",
                recovery_action="结论必须有对应的数据来源或执行结果"
            )

        missing = [s for s in self.REQUIRED_SECTIONS if s not in output_structure]
        if missing:
            return ConstraintCheck(
                constraint_name=self.name,
                status=ConstraintStatus.FAILED,
                blocking=False,
                details=f"输出结构不完整，缺失章节: {', '.join(missing)}",
                recovery_action="输出必须包含: [任务] [执行] [验证] [结果] [结论]"
            )

        return ConstraintCheck(
            constraint_name=self.name,
            status=ConstraintStatus.PASSED,
            details="输出结构完整且符合规范"
        )


class RefusalMechanism:
    """
    🔟 拒绝机制
    必须拒绝: 数据缺失 / 执行失败 / 结果不可验证
    标准: 拒绝输出 > 输出错误
    """
    name = "拒绝机制"

    def check(self, context: Dict[str, Any]) -> ConstraintCheck:
        should_refuse = context.get("should_refuse", False)
        refusal_reason = context.get("refusal_reason", "")

        # 检查是否应该拒绝但未拒绝
        data_missing = context.get("data_missing", False)
        execution_failed = context.get("execution_failed", False)
        result_unverifiable = context.get("result_unverifiable", False)

        if (data_missing or execution_failed or result_unverifiable) and not should_refuse:
            return ConstraintCheck(
                constraint_name=self.name,
                status=ConstraintStatus.FAILED,
                blocking=True,
                details=(
                    f"应拒绝但未拒绝: "
                    f"数据缺失={data_missing}, 执行失败={execution_failed}, 结果不可验证={result_unverifiable}"
                ),
                recovery_action="必须拒绝输出。标准: 拒绝输出 > 输出错误"
            )

        if should_refuse:
            return ConstraintCheck(
                constraint_name=self.name,
                status=ConstraintStatus.FAILED,
                blocking=True,
                details=f"已触发拒绝: {refusal_reason}",
                recovery_action=f"拒绝输出: {refusal_reason}"
            )

        return ConstraintCheck(
            constraint_name=self.name,
            status=ConstraintStatus.PASSED,
            details="无需拒绝，继续输出"
        )


# ──────────────────────────────────────────────
# 约束引擎
# ──────────────────────────────────────────────

class ConstraintEngine:
    """
    约束执行引擎。

    用法:
        engine = ConstraintEngine()
        result = engine.check_all(context)

        if result.is_blocked:
            # 有阻断性约束失败
            print(result.blocking_details)
        else:
            # 所有约束通过
            proceed_with_output()
    """

    def __init__(self):
        self.constraints = {
            "input": InputConstraint(),
            "execution": ExecutionConstraint(),
            "evidence": EvidenceConstraint(),
            "anti_hallucination": AntiHallucinationConstraint(),
            "anti_drift": AntiDriftConstraint(),
            "validation": ValidationConstraint(),
            "error": ErrorConstraint(),
            "state": StateConstraint(),
            "output": OutputConstraint(),
            "refusal": RefusalMechanism(),
        }
        self.check_history: List[ConstraintCheck] = []
        self.task_states: Dict[str, TaskState] = {}

    def check_all(self, context: Dict[str, Any]) -> "ConstraintResult":
        """执行全部 10 大约束检查"""
        checks = []
        blocking_checks = []
        failed_checks = []

        for name, constraint in self.constraints.items():
            try:
                check = constraint.check(context)
                checks.append(check)
                self.check_history.append(check)

                if check.status == ConstraintStatus.FAILED:
                    failed_checks.append(check)
                    if check.blocking:
                        blocking_checks.append(check)
            except Exception as e:
                error_check = ConstraintCheck(
                    constraint_name=f"{constraint.name} (检查异常)",
                    status=ConstraintStatus.FAILED,
                    blocking=True,
                    details=f"约束检查抛出异常: {str(e)}",
                    recovery_action="修复约束检查逻辑后重试"
                )
                checks.append(error_check)
                self.check_history.append(error_check)
                blocking_checks.append(error_check)
                failed_checks.append(error_check)

        return ConstraintResult(
            total_checks=len(checks),
            passed=len(checks) - len(failed_checks),
            failed=len(failed_checks),
            blocking=len(blocking_checks),
            checks=checks,
            blocking_checks=blocking_checks,
            failed_checks=failed_checks,
        )

    def check_single(self, constraint_name: str, context: Dict[str, Any]) -> ConstraintCheck:
        """执行单个约束检查"""
        if constraint_name not in self.constraints:
            return ConstraintCheck(
                constraint_name=constraint_name,
                status=ConstraintStatus.FAILED,
                blocking=True,
                details=f"未知约束: {constraint_name}",
                recovery_action=f"可用约束: {', '.join(self.constraints.keys())}"
            )

        check = self.constraints[constraint_name].check(context)
        self.check_history.append(check)
        return check

    def create_task_state(self, task_id: str, goal: str) -> TaskState:
        """创建任务状态记录"""
        state = TaskState(task_id=task_id, original_goal=goal)
        self.task_states[task_id] = state
        return state

    def update_task_state(self, task_id: str, **kwargs) -> Optional[TaskState]:
        """更新任务状态"""
        if task_id not in self.task_states:
            return None
        state = self.task_states[task_id]
        for key, value in kwargs.items():
            if hasattr(state, key):
                setattr(state, key, value)
        return state

    def get_task_state(self, task_id: str) -> Optional[TaskState]:
        """获取任务状态"""
        return self.task_states.get(task_id)

    def get_statistics(self) -> Dict[str, Any]:
        """获取约束检查统计"""
        total = len(self.check_history)
        if total == 0:
            return {"total_checks": 0}

        passed = sum(1 for c in self.check_history if c.status == ConstraintStatus.PASSED)
        failed = sum(1 for c in self.check_history if c.status == ConstraintStatus.FAILED)
        blocking = sum(1 for c in self.check_history if c.blocking and c.status == ConstraintStatus.FAILED)

        return {
            "total_checks": total,
            "passed": passed,
            "failed": failed,
            "blocking_failures": blocking,
            "pass_rate": passed / total if total > 0 else 0,
            "active_tasks": len(self.task_states),
        }


@dataclass
class ConstraintResult:
    """约束检查结果"""
    total_checks: int
    passed: int
    failed: int
    blocking: int
    checks: List[ConstraintCheck]
    blocking_checks: List[ConstraintCheck]
    failed_checks: List[ConstraintCheck]

    @property
    def is_clean(self) -> bool:
        """是否完全通过"""
        return self.failed == 0

    @property
    def is_blocked(self) -> bool:
        """是否被阻断"""
        return self.blocking > 0

    @property
    def blocking_details(self) -> str:
        """阻断详情"""
        if not self.blocking_checks:
            return ""
        lines = ["约束阻断检查:"]
        for c in self.blocking_checks:
            lines.append(f"  ❌ {c.constraint_name}: {c.details}")
            if c.recovery_action:
                lines.append(f"     → {c.recovery_action}")
        return "\n".join(lines)

    @property
    def summary(self) -> str:
        """摘要"""
        if self.is_clean:
            return f"✅ 约束检查通过 ({self.passed}/{self.total_checks})"
        else:
            status = f"❌ 阻断 ({self.blocking} 项)" if self.is_blocked else f"⚠️ 警告 ({self.failed} 项)"
            return f"{status} — 通过 {self.passed}/{self.total_checks}"


# ──────────────────────────────────────────────
# 便捷函数
# ──────────────────────────────────────────────

_global_engine: Optional[ConstraintEngine] = None


def get_constraint_engine() -> ConstraintEngine:
    """获取全局约束引擎实例"""
    global _global_engine
    if _global_engine is None:
        _global_engine = ConstraintEngine()
    return _global_engine


def check_constraints(context: Dict[str, Any]) -> ConstraintResult:
    """便捷函数: 执行全部约束检查"""
    return get_constraint_engine().check_all(context)


def must_refuse(context: Dict[str, Any]) -> Optional[str]:
    """
    检查是否必须拒绝执行。
    返回拒绝原因字符串，如果不需要拒绝则返回 None。
    """
    result = check_constraints(context)
    if result.is_blocked:
        return result.blocking_details
    return None


# ──────────────────────────────────────────────
# 5 大核心原则验证器
# ──────────────────────────────────────────────

class CorePrincipleValidator:
    """
    5 大核心原则验证器。

    原则 1: 没有执行，不允许说话
    原则 2: 没有证据，结论无效
    原则 3: 无法验证，必须拒绝
    原则 4: 偏离目标，立即停止
    原则 5: Agent 只能做"被证明的事"，不能做"看起来对的事"
    """

    PRINCIPLES = {
        1: {
            "name": "没有执行，不允许说话",
            "check_key": "has_execution",
        },
        2: {
            "name": "没有证据，结论无效",
            "check_key": "has_evidence",
        },
        3: {
            "name": "无法验证，必须拒绝",
            "check_key": "is_validated",
        },
        4: {
            "name": "偏离目标，立即停止",
            "check_key": "on_target",
        },
        5: {
            "name": "只能做被证明的事",
            "check_key": "is_proven",
        },
    }

    def validate(self, context: Dict[str, Any]) -> Dict[int, bool]:
        """
        验证 5 大核心原则。
        返回 {原则编号: 是否通过}
        """
        results = {}
        for num, principle in self.PRINCIPLES.items():
            key = principle["check_key"]
            results[num] = context.get(key, False)
        return results

    def all_passed(self, results: Dict[int, bool]) -> bool:
        """检查是否全部通过"""
        return all(results.values())

    def failed_principles(self, results: Dict[int, bool]) -> List[str]:
        """获取未通过的原则列表"""
        failed = []
        for num, passed in results.items():
            if not passed:
                failed.append(f"原则 {num}: {self.PRINCIPLES[num]['name']}")
        return failed
