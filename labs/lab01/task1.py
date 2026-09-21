
import os
import random
import sys

sys.path.append(
    os.path.abspath(os.path.join(os.path.dirname(__file__), "../../"))
)

from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER

passwords = [
    "InfoS3c@2023", "simple123", "Def3ns3@Key", "public",
    "Encrypt3d#Pass", "basic123", "Secur3@Analysis", "temp123",
    "Pr0t3ct@Data", "default",
]

criteria = {
    "min_length": 8,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

forbidden_passwords = {
    "simple123", "public", "basic123", "temp123", "default", "guest",
}


def duplicate_random_passwords(password_list, count=3):
    updated_list = list(password_list)
    random_indexes = random.sample(range(len(password_list)), count)
    for index in random_indexes:
        updated_list.append(password_list[index])
    return updated_list


def check_character_groups(password):
    return {
        "digit": any(char.isdigit() for char in password),
        "upper": any(char.isupper() for char in password),
        "lower": any(char.islower() for char in password),
        "special": any(not char.isalnum() for char in password),
    }

def meets_required_criteria(groups, rules):
    if rules.get("require_digits") and not groups["digit"]:
        return False
    if rules.get("require_upper") and not groups["upper"]:
        return False
    if rules.get("require_special") and not groups["special"]:
        return False
    return True


def evaluate_password(password, rules, forbidden, all_passwords):
    if password in forbidden or len(password) < rules["min_length"]:
        return "Forbidden"

    groups = check_character_groups(password)
    matched_groups = sum(groups.values())

    if meets_required_criteria(groups, rules):
        is_long_enough = len(password) >= rules["min_length"] + 4
        is_unique = all_passwords.count(password) == 1
        if is_long_enough and is_unique:
            return "Very strong"
        return "Strong"

    if matched_groups <= 1:
        return "Weak"
    return "Medium"


def analyze_passwords(password_list, rules, forbidden):
    results = []
    for password in password_list:
        level = evaluate_password(password, rules, forbidden, password_list)
        results.append((password, level))
    return results


def print_report(results, student_name, group_name, variant):
    print(f"Student: {student_name} | Group: {group_name} | "
          f"Variant: {variant}")
    print(f"{'Password':<20}{'Strength level':<15}")
    print("-" * 35)
    for password, level in results:
        print(f"{password:<20}{level:<15}")


def main():
    extended_passwords = duplicate_random_passwords(passwords, count=3)
    results = analyze_passwords(
        extended_passwords, criteria, forbidden_passwords
    )
    print_report(results, STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER)


if __name__ == "__main__":
    main()