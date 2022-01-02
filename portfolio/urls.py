from django.urls import path
from . import views

urlpatterns = [
    path('', views.home, name="home"),

    path('send_email', views.send_message, name="send email"),

    path('login/', views.login_page, name="login page"),
    path('auth/', views.auth_page, name="auth page"),

    path('admin/', views.admin, name="admin"),
    path('details/', views.details, name="details"),
    path('documents/', views.documents, name="documents"),
    path('hobbies/', views.hobbies, name="hobbies"),
    path('education/', views.education, name="education"),
    path('work/', views.work, name="work"),
    path('strengths/', views.strengths, name="strengths"),
    path('projects/', views.projects, name="projects"),
    path('technologies/', views.technologies, name="technologies"),
    path('password/', views.password_page, name="password page"),
    path('forgot-password', views.forgot_password_page, name="forgot password page"),

    path('get_document', views.get_document, name="get document"),

    path('admin/login', views.login, name="login"),
    path('admin/2fa', views.two_factor_auth, name="send 2fa"),
    path('admin/auth', views.authenticate, name="authenticate"),
    path('admin/logout', views.logout, name="logout"),
    path('admin/update', views.update_details, name="update details"),
    path('admin/reset_password', views.reset_password, name="reset password"),
    path('admin/send_forgot_password', views.send_forgot_password_link, name="send forgot password link"),
    path('admin/reset_forgot_password', views.reset_forgotten_password, name="reset forgotten password"),
    path('admin/upload_document', views.upload_document, name="upload document"),
    path('admin/delete_document', views.delete_document, name="delete document"),
    path('admin/verify', views.verify_email, name="verify email"),
    path('admin/save_address', views.save_address, name="save address"),

    path('admin/add_technology', views.add_technology, name="add technology"),
    path('admin/update_technology', views.update_technology, name="update technology"),
    path('admin/delete_technology', views.delete_technology, name="delete technology"),

    path('admin/add_hobby', views.add_hobby, name="add hobby"),
    path('admin/update_hobby', views.update_hobby, name="update hobby"),
    path('admin/delete_hobby', views.delete_hobby, name="delete hobby"),
    path('admin/add_skill', views.add_skill, name="add skill"),
    path('admin/update_skill', views.update_skill, name="update skill"),
    path('admin/delete_skill', views.delete_skill, name="delete skill"),
    path('admin/add_work', views.add_work, name="add work"),
    path('admin/update_work', views.update_work, name="update work"),
    path('admin/delete_work', views.delete_work, name="delete work"),

    path('admin/add_project', views.add_project, name="add project"),
    path('admin/update_project', views.update_project, name="update project"),
    path('admin/delete_project', views.delete_project, name="delete project"),

    path('admin/add_education', views.add_education, name="add education"),
    path('admin/update_education', views.update_education, name="update education"),
    path('admin/delete_education', views.delete_education, name="delete education"),
    path('admin/refresh', views.refresh_token_view, name="refresh token"),
]
