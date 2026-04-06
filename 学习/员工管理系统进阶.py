import re  # 正则表达式，用于格式校验
import json  # 用于数据持久化（保存为JSON文件）
from datetime import datetime
from pathlib import Path  # 更安全的文件路径管理


# ==================================================
# 一、实体层（Entity Layer）
# ==================================================
# 只负责"数据结构"和"数据逻辑"
# 不处理输入输出，不处理业务流程
# ==================================================

class Employee:
    """
    员工实体类
    只负责保存员工数据 + 计算动态年龄
    """

    def __init__(self, emp_id, first_name, last_name, id_card, gender, phone, department):
        self.emp_id = emp_id
        self.first_name = first_name
        self.last_name = last_name
        self.id_card = id_card
        self.gender = gender
        self.phone = phone
        self.department = department

    # 使用 @property 实现"动态计算属性"
    # 每次访问 emp.age 都会重新计算
    @property
    def age(self):
        """
        根据身份证第7-14位计算年龄
        假设身份证格式包含出生日期 YYYYMMDD
        """
        birth_str = self.id_card[6:14]
        birth_date = datetime.strptime(birth_str, "%Y%m%d")
        today = datetime.today()

        age = today.year - birth_date.year
        if (today.month, today.day) < (birth_date.month, birth_date.day):
            age -= 1

        return age

    def to_dict(self):
        """
        将对象转换为字典（用于保存到JSON）
        """
        return self.__dict__

    @staticmethod
    def from_dict(data):
        """
        从字典恢复为对象
        """
        return Employee(**data)


# ==================================================
# 二、校验层（Validation Layer）
# ==================================================
# 专门负责数据合法性校验
# 不负责存储，不负责UI
# ==================================================

class Validator:

    @staticmethod
    def validate_id_card(id_card):
        if not re.fullmatch(r"[A-Za-z0-9]+", id_card):
            raise ValueError("身份证只能包含字母和数字")

        if len(id_card) < 15:
            raise ValueError("身份证长度不合法")

    @staticmethod
    def validate_gender(gender):
        if gender.lower() not in ['男', '女', 'male', 'female']:
            raise ValueError("性别只能输入 男/女/male/female")

    @staticmethod
    def validate_phone(phone):
        if not phone.isdigit():
            raise ValueError("电话只能为数字")

        if len(phone) < 7:
            raise ValueError("电话长度不能少于7位")

    @staticmethod
    def validate_name(name):
        if not re.fullmatch(r"[\u4e00-\u9fa5a-zA-Z]+", name):
            raise ValueError("姓名只能为中文或字母")

    @staticmethod
    def validate_department(dept):
        if not dept.isalpha():
            raise ValueError("部门只能为字母")


# ==================================================
# 三、服务层（Service Layer）
# ==================================================
# 负责业务逻辑 + 数据持久化
# 不负责UI
# ==================================================

class EmployeeService:

    def __init__(self, storage_file="employees.json"):
        self.storage_file = Path(storage_file)
        self.employees = self._load()

    # ---------- 私有方法：加载数据 ----------
    def _load(self):
        """
        从JSON文件读取员工数据
        """
        if not self.storage_file.exists():
            return []

        with open(self.storage_file, "r", encoding="utf-8") as f:
            data = json.load(f)
            return [Employee.from_dict(d) for d in data]

    # ---------- 私有方法：保存数据 ----------
    def _save(self):
        """
        保存数据到JSON文件
        """
        with open(self.storage_file, "w", encoding="utf-8") as f:
            json.dump(
                [e.to_dict() for e in self.employees],
                f,
                ensure_ascii=False,
                indent=4
            )

    # ---------- 添加员工 ----------
    def add_employee(self, employee):
        if self.get_employee(employee.emp_id):
            raise ValueError("工号已存在")

        self.employees.append(employee)
        self._save()

    # ---------- 查询员工 ----------
    def get_employee(self, emp_id):
        for emp in self.employees:
            if emp.emp_id == emp_id:
                return emp
        return None

    # ---------- 删除员工 ----------
    def delete_employee(self, emp_id):
        emp = self.get_employee(emp_id)
        if not emp:
            raise ValueError("员工不存在")

        self.employees.remove(emp)
        self._save()

    # ---------- 更新员工 ----------
    def update_employee(self, emp_id, **kwargs):
        emp = self.get_employee(emp_id)

        if not emp:
            raise ValueError("员工不存在")

        # 动态更新属性
        for key, value in kwargs.items():
            setattr(emp, key, value)

        self._save()


# ==================================================
# 四、控制层（CLI交互层）
# ==================================================
# 只负责：
# 1. 用户输入
# 2. 调用服务层
# 3. 捕获异常
# ==================================================

class CLI:

    def __init__(self):
        self.service = EmployeeService()

    def run(self):
        while True:
            print("\n========== 员工管理系统 ==========")
            print("1 添加员工")
            print("2 查询员工")
            print("3 修改员工")
            print("4 删除员工")
            print("5 退出")

            choice = input("请选择操作：").strip()

            try:
                if choice == "1":
                    self.add()
                elif choice == "2":
                    self.search()
                elif choice == "3":
                    self.modify()
                elif choice == "4":
                    self.delete()
                elif choice == "5":
                    print("系统已退出")
                    break
                else:
                    print("输入无效")
            except Exception as e:
                print(f"发生错误：{e}")

    # ---------------- 添加 ----------------
    def add(self):
        # 实时校验每个字段
        while True:
            emp_id = input("工号：").strip()
            if emp_id:
                break
            print("工号不能为空，请重新输入！")

        while True:
            first_name = input("姓：").strip()
            try:
                Validator.validate_name(first_name)
                break
            except ValueError as e:
                print(f"{e}，请重新输入！")

        while True:
            last_name = input("名：").strip()
            try:
                Validator.validate_name(last_name)
                break
            except ValueError as e:
                print(f"{e}，请重新输入！")

        while True:
            id_card = input("身份证：").strip()
            try:
                Validator.validate_id_card(id_card)
                break
            except ValueError as e:
                print(f"{e}，请重新输入！")

        while True:
            gender = input("性别：").strip()
            try:
                Validator.validate_gender(gender)
                break
            except ValueError as e:
                print(f"{e}，请重新输入！")

        while True:
            phone = input("电话：").strip()
            try:
                Validator.validate_phone(phone)
                break
            except ValueError as e:
                print(f"{e}，请重新输入！")

        while True:
            department = input("部门：").strip()
            try:
                Validator.validate_department(department)
                break
            except ValueError as e:
                print(f"{e}，请重新输入！")

        emp = Employee(emp_id, first_name, last_name, id_card, gender, phone, department)

        # 显示自动计算的年龄
        print(f"\n根据身份证计算的年龄：{emp.age}岁")

        self.service.add_employee(emp)

        print("添加成功")

    # ---------------- 查询 ----------------
    def search(self):
        emp_id = input("工号：").strip()
        emp = self.service.get_employee(emp_id)

        if not emp:
            print("未找到员工")
            return

        print(f"""
工号：{emp.emp_id}
姓名：{emp.first_name}{emp.last_name}
年龄：{emp.age}
性别：{emp.gender}
电话：{emp.phone}
部门：{emp.department}
""")

    # ---------------- 删除 ----------------
    def delete(self):
        emp_id = input("工号：").strip()
        emp = self.service.get_employee(emp_id)

        if not emp:
            print("未找到员工")
            return

        # 显示员工信息
        print(f"\n===== 员工信息 =====")
        print(f"工号：{emp.emp_id}")
        print(f"姓名：{emp.first_name}{emp.last_name}")
        print(f"部门：{emp.department}")
        print(f"年龄：{emp.age}岁")
        print(f"===================")

        # 确认删除
        while True:
            confirm = input("\n确认删除该员工？(y/n)：").strip().lower()
            if confirm == 'y':
                self.service.delete_employee(emp_id)
                print("删除成功")
                print("警告：删除操作不可逆！")
                break
            elif confirm == 'n':
                print("删除操作已取消")
                break
            else:
                print("请输入 'y' 确认删除或 'n' 取消")

    # ---------------- 修改 ----------------
    def modify(self):
        emp_id = input("工号：").strip()
        emp = self.service.get_employee(emp_id)

        if not emp:
            print("未找到员工")
            return

        phone = input("新电话（回车跳过）：").strip()
        department = input("新部门（回车跳过）：").strip()

        updates = {}

        if phone:
            while True:
                try:
                    Validator.validate_phone(phone)
                    updates["phone"] = phone
                    break
                except ValueError as e:
                    print(f"{e}，请重新输入！")
                    phone = input("新电话（回车跳过）：").strip()
                    if not phone:
                        break

        if department:
            while True:
                try:
                    Validator.validate_department(department)
                    updates["department"] = department
                    break
                except ValueError as e:
                    print(f"{e}，请重新输入！")
                    department = input("新部门（回车跳过）：").strip()
                    if not department:
                        break

        self.service.update_employee(emp_id, **updates)

        print("修改成功")


# ==================================================
# 程序入口
# ==================================================

if __name__ == "__main__":
    CLI().run()