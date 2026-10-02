
import os
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

users = {
    "red_team_lead": {
        "role": "red_team", "clearance": 4,
        "department": "Red Team", "active": True,
    },
    "blue_team_analyst": {
        "role": "blue_team", "clearance": 3,
        "department": "Blue Team", "active": True,
    },
    "purple_team_coord": {
        "role": "purple_team", "clearance": 3,
        "department": "Purple Team", "active": True,
    },
    "student_intern": {
        "role": "student", "clearance": 1,
        "department": "Academia", "active": True,
    },
    "retired_expert": {
        "role": "retired", "clearance": 2,
        "department": "Emeritus", "active": False,
    },
}

resources = [
    ("attack_scenarios", 4), ("defense_playbooks", 3),
    ("exercise_plans", 3), ("research_papers", 1),
    ("exploit_tools", 4), ("student_resources", 1),
    ("simulation_results", 3), ("red_team_tools", 4),
    ("blue_team_reports", 3), ("public_research", 1),
]

security_levels = ("Academic", "Operational", "Tactical", "Strategic")

blocked_users = {"retired_expert", "academic_violator", "leaked_account"}


def print_resources(resource_list, level_names):
    print("Resources in the system:")
    for name, level in resource_list:
        level_name = level_names[level - 1]
        print(f"  {name:<25} -> {level_name}")


def check_access(username, resource_level, user_db, blocked_set):
    if username not in user_db:
        return False, "User not found"

    if username in blocked_set:
        return False, "User is blocked"

    user = user_db[username]
    if not user["active"]:
        return False, "Account inactive"

    if user["clearance"] >= resource_level:
        return True, ""

    return False, "Insufficient clearance"


def run_access_checks(user_db, resource_list, blocked_set):
    report_lines = []
    for username in user_db:
        for resource_name, resource_level in resource_list:
            allowed, reason = check_access(
                username, resource_level, user_db, blocked_set
            )
            decision = "ALLOW" if allowed else f"DENY ({reason})"
            line = (f"user={username} resource={resource_name} "
                    f"-> {decision}")
            report_lines.append(line)
    return report_lines


def main():
    print(f"Student: {STUDENT_NAME} | Group: {GROUP_NAME} | "
          f"Variant: {VARIANT_NUMBER}")
    print_resources(resources, security_levels)
    print()
    for line in run_access_checks(users, resources, blocked_users):
        print(line)


if __name__ == "__main__":
    main()