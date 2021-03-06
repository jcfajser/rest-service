package com.example.restservice.employee;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.*;

import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("management/api/v1/employees")
public class EmployeeManagementController {
    private static final List<Employee> EMPLOYEES = Arrays.asList(
            new Employee(1, "James Bond"),
            new Employee(2, "Maria Jones"),
            new Employee(3, "Anna Smith")
    );

//    hasRole('ROLE_') hasAnyRole('ROLE_') hasAuthority('permission') hasAnyAuthority('permission')

    @GetMapping
    @PreAuthorize("hasAnyRole('ROLE_ADMIN', 'ROLE_ADMINTRAINEE')")
    public static List<Employee> getAllEmployees() {
        System.out.println("getAllEmployees");
        return EMPLOYEES;
    }

    @PostMapping
    @PreAuthorize("hasAuthority('employee:write')")
    public void registerNewEmployee(@RequestBody Employee employee) {
        System.out.println("registerNewEmployee");
        System.out.println(employee);
    }

    @DeleteMapping(path = "{employeeId}")
    @PreAuthorize("hasAuthority('employee:write')")
    public void deleteEmployee(@PathVariable("employeeId") Integer employeeId) {
        System.out.println("deleteEmployee");
        System.out.println(employeeId);
    }

    @PutMapping(path = "{employeeId}")
    @PreAuthorize("hasAuthority('employee:write')")
    public void updateEmployee(@PathVariable("employeeId") Integer employeeId, @RequestBody Employee employee){
        System.out.println("updateEmployee");
        System.out.println(String.format("%s %s", employeeId, employee));
    }
}
