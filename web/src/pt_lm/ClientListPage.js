// Copyright 2021 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

import React from "react";
import {Link} from "react-router-dom";
import {Button, Switch, Table, Upload} from "antd";
import {UploadOutlined} from "@ant-design/icons";
import moment from "moment";
import * as OrganizationBackend from "../backend/OrganizationBackend";
import * as Setting from "../Setting";
import * as UserBackend from "../backend/UserBackend";
import i18next from "i18next";
import BaseListPage from "../BaseListPage";
import PopconfirmModal from "../common/modal/PopconfirmModal";

class UserListPage extends BaseListPage {
  constructor(props) {
    super(props);
    this.state = {
      ...this.state,
      organizationName: this.props.organizationName ?? this.props.match?.params.organizationName ?? this.props.account.owner,
      organization: null,
    };
  }

  UNSAFE_componentWillMount() {
    super.UNSAFE_componentWillMount();
    this.getOrganization(this.state.organizationName);
  }

  newUser() {
    const randomName = Setting.getRandomName();
    const owner = Setting.isDefaultOrganizationSelected(this.props.account) ? this.state.organizationName : Setting.getRequestOrganization(this.props.account);
    return {
      owner: owner,
      name: `user_${randomName}`,
      createdTime: moment().format(),
      type: "normal-user",
      password: "123",
      passwordSalt: "",
      displayName: `New User - ${randomName}`,
      avatar: "https://static.vecteezy.com/system/resources/thumbnails/000/439/863/small/Basic_Ui__28186_29.jpg",
      email: `${randomName}@example.com`,
      phone: Setting.getRandomNumber(),
      countryCode: "",
      address: [],
      affiliation: "Example Inc.",
      tag: "client",
      region: "",
      isAdmin: false,
      isGlobalAdmin: false,
      IsForbidden: false,
      properties: {
        "ИНН": "",
        "КПП": "",
        "ФИО менеджера": "",
      },

      score: 0,
      isDeleted: false,
      signupApplication: (owner === "built-in" ? "app-built-in" : owner),
    };
  }

  addUser() {
    const newUser = this.newUser();
    UserBackend.addUser(newUser)
      .then((res) => {
        if (res.status === "ok") {
          sessionStorage.setItem("userListUrl", window.location.pathname);
          this.props.history.push({pathname: `/clients/${newUser.owner}/${newUser.name}`, mode: "add"});
          Setting.showMessage("success", i18next.t("general:Successfully added"));
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to add")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  deleteUser(i) {
    UserBackend.deleteUser(this.state.data[i])
      .then((res) => {
        if (res.status === "ok") {
          Setting.showMessage("success", i18next.t("general:Successfully deleted"));
          this.setState({
            data: Setting.deleteRow(this.state.data, i),
            pagination: {total: this.state.pagination.total - 1},
          });
        } else {
          Setting.showMessage("error", `${i18next.t("general:Failed to delete")}: ${res.msg}`);
        }
      })
      .catch(error => {
        Setting.showMessage("error", `${i18next.t("general:Failed to connect to server")}: ${error}`);
      });
  }

  uploadFile(info) {
    const {status, response: res} = info.file;
    if (status === "done") {
      if (res.status === "ok") {
        Setting.showMessage("success", "Users uploaded successfully, refreshing the page");

        const {pagination} = this.state;
        this.fetch({pagination});
      } else {
        Setting.showMessage("error", `Users failed to upload: ${res.msg}`);
      }
    } else if (status === "error") {
      Setting.showMessage("error", "File failed to upload");
    }
  }

  renderUpload() {
    const props = {
      name: "file",
      accept: ".xlsx",
      method: "post",
      action: `${Setting.ServerUrl}/api/upload-users`,
      withCredentials: true,
      onChange: (info) => {
        this.uploadFile(info);
      },
    };

    return (
      <Upload {...props}>
        <Button type="primary" size="small">
          <UploadOutlined /> {i18next.t("user:Upload (.xlsx)")}
        </Button>
      </Upload>
    );
  }

  renderTable(users) {
    const columns = [
      {
        title: i18next.t("general:Organization"),
        dataIndex: "owner",
        key: "owner",
        width: (Setting.isMobile()) ? "100px" : "120px",
        fixed: "left",
        sorter: true,
        ...this.getColumnSearchProps("owner", true),
        render: (text, record, index) => {
          return (
            <Link to={`/organizations/${text}`}>
              {text}
            </Link>
          );
        },
      },
      {
        title: i18next.t("general:Indentity"),
        dataIndex: "name",
        key: "name",
        width: (Setting.isMobile()) ? "80px" : "110px",
        fixed: "left",
        sorter: true,
        ...this.getColumnSearchProps("name", true),
        render: (text, record, index) => {
          return (
            <Link to={`/users/${record.owner}/${text}`}>
              {text}
            </Link>
          );
        },
      },
      {
        title: i18next.t("general:Наименование"),
        dataIndex: "displayName",
        key: "displayName",
        // width: '100px',
        sorter: true,
        ...this.getColumnSearchProps("displayName", true),
      },
      {
        title: i18next.t("general:ИНН"),
        dataIndex: "user:inn",
        key: "user:inn",
        sorter: false,
        render: (text, record, index) => {
          return (
            <span>
              {record?.properties?.["ИНН"] || ""}
            </span>
          );
        },
      },
      {
        title: i18next.t("Email"),
        dataIndex: "email",
        key: "email",
        width: "160px",
        sorter: true,
        ...this.getColumnSearchProps("email", true),
        render: (text, record, index) => {
          return (
            <a href={`mailto:${text}`}>
              {text}
            </a>
          );
        },
      },
      {
        title: i18next.t("general:Phone"),
        dataIndex: "phone",
        key: "phone",
        width: "120px",
        sorter: true,
        ...this.getColumnSearchProps("phone", true),
      },
      {
        title: i18next.t("general:Дата создания"),
        dataIndex: "createdTime",
        key: "createdTime",
        width: "160px",
        sorter: true,
        render: (text, record, index) => {
          return Setting.getFormattedDate(text);
        },
      },
      {
        title: i18next.t("user:Отключен"),
        dataIndex: "isForbidden",
        key: "isForbidden",
        width: "110px",
        sorter: true,
        render: (text, record, index) => {
          return (
            <Switch disabled checkedChildren="ON" unCheckedChildren="OFF" checked={text} />
          );
        },
      },
      {
        title: i18next.t("general:Action"),
        dataIndex: "",
        key: "op",
        width: "190px",
        fixed: (Setting.isMobile()) ? "false" : "right",
        render: (text, record, index) => {
          const disabled = (record.owner === this.props.account.owner && record.name === this.props.account.name);
          return (
            <div>
              <Button style={{marginTop: "10px", marginBottom: "10px", marginRight: "10px"}} type="primary" onClick={() => {
                sessionStorage.setItem("userListUrl", window.location.pathname);
                this.props.history.push(`/clients/${record.owner}/${record.name}`);
              }}>{i18next.t("general:Edit")}</Button>
              <PopconfirmModal
                title={i18next.t("general:Sure to delete") + `: ${record.name} ?`}
                onConfirm={() => this.deleteUser(index)}
                disabled={disabled}
              >
              </PopconfirmModal>
            </div>
          );
        },
      },
    ];

    const paginationProps = {
      total: this.state.pagination.total,
      showQuickJumper: true,
      showSizeChanger: true,
      defaultPageSize: 50,
      pageSizeOptions: [50, 100],
      showTotal: () => i18next.t("general:{total} in total").replace("{total}", this.state.pagination.total),
    };

    return (
      <div>
        <Table scroll={{x: "max-content"}} columns={columns} dataSource={users} rowKey={(record) => `${record.owner}/${record.name}`} size="middle" bordered pagination={paginationProps}
          title={() => (
            <div>
              {i18next.t("general:Заказчики")}&nbsp;&nbsp;&nbsp;&nbsp;
              <Button style={{marginRight: "5px"}} type="primary" size="small" onClick={this.addUser.bind(this)}>{i18next.t("general:Add")}</Button>
            </div>
          )}
          loading={this.state.loading}
          onChange={this.handleTableChange}
        />
      </div>
    );
  }

  fetch = (params = {}) => {
    let field = params.searchedColumn, value = params.searchText;

    field = "tag";
    value = "client";

    const sortField = params.sortField, sortOrder = params.sortOrder;
    this.setState({loading: true});
    if (this.props.match.params.organizationName === undefined) {
      (Setting.isDefaultOrganizationSelected(this.props.account) ? UserBackend.getGlobalUsers(params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder) : UserBackend.getUsers(Setting.getRequestOrganization(this.props.account), params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder))
        .then((res) => {
          if (res.status === "ok") {
            this.setState({
              loading: false,
              data: res.data,
              pagination: {
                ...params.pagination,
                total: res.data2,
              },
              searchText: params.searchText,
              searchedColumn: params.searchedColumn,
            });

            const users = res.data;
            if (users.length > 0) {
              this.getOrganization(users[0].owner);
            } else {
              this.getOrganization(this.state.organizationName);
            }
          } else {
            if (Setting.isResponseDenied(res)) {
              this.setState({
                loading: false,
                isAuthorized: false,
              });
            }
          }
        });
    } else {
      UserBackend.getUsers(this.props.match.params.organizationName, params.pagination.current, params.pagination.pageSize, field, value, sortField, sortOrder)
        .then((res) => {
          if (res.status === "ok") {
            this.setState({
              loading: false,
              data: res.data,
              pagination: {
                ...params.pagination,
                total: res.data2,
              },
              searchText: params.searchText,
              searchedColumn: params.searchedColumn,
            });

            const users = res.data;
            if (users.length > 0) {
              this.getOrganization(users[0].owner);
            } else {
              this.getOrganization(this.state.organizationName);
            }
          } else {
            if (Setting.isResponseDenied(res)) {
              this.setState({
                loading: false,
                isAuthorized: false,
              });
            }
          }
        });
    }
  };

  getOrganization(organizationName) {
    OrganizationBackend.getOrganization("admin", organizationName)
      .then((res) => {
        if (res.status === "ok") {
          this.setState({
            organization: res.data,
          });
        } else {
          Setting.showMessage("error", `Failed to get organization: ${res.msg}`);
        }
      });
  }
}

export default UserListPage;
