<?php

class QueryDBHelper
{
  private $ci;
  public $db;
  function __construct()
  {
    $this->ci = &get_instance();
    $this->ci->load->database();
    $this->db = $this->ci->db;
  }

  function from(string $table)
  {
    return $this->db->from($table);
  }

  function where($column, $value = null)
  {
    if ($value == null) return $this->db->where($column);
    return $this->db->where($column, $value);
  }

  function get($table = null)
  {
    if ($table == null) return $this->db->get();
    else return $this->db->get($table);
  }

  function get_row($table)
  {
    return $this->get($table)->row();
  }

  function get_row_array($table)
  {
    return $this->get($table)->row_array();
  }

  function get_result($table)
  {
    return $this->get($table)->result();
  }

  function get_result_array($table)
  {
    return $this->get($table)->result_array();
  }

  function get_where(string $table, array $where)
  {
    return $this->db->get_where($table, $where);
  }

  function get_where_row(string $table, array $where)
  {
    return $this->get_where($table, $where)->row();
  }

  function get_where_row_array(string $table, array $where)
  {
    return $this->get_where($table, $where)->row_array();
  }

  function get_where_result(string $table, array $where)
  {
    return $this->get_where($table, $where)->result();
  }

  function get_where_result_array(string $table, array $where)
  {
    return $this->get_where($table, $where)->result_array();
  }

  function get_order_by_result(string $table, string $column, string $sort)
  {
    $this->db->order_by($column, $sort);
    return $this->db->get($table)->result();
  }

  function insert(string $table, array $data)
  {
    $this->db->insert($table, $data);
    return $this->db->insert_id();
  }

  function insert_batch(string $table, array $data)
  {
    $this->db->insert_batch($table, $data);
  }

  function delete_where(string $table, array $where)
  {
    $this->db->where($where);
    $this->db->delete($table);
  }

  function update_where(string $table, array $data, array $where)
  {
    $this->db->where($where);
    $this->db->update($table, $data);
  }

  function get_limit(string $table, $limit, $offset = null)
  {
    if ($offset != null)
      $this->db->limit($limit, $offset);
    else $this->db->limit($limit);
    return $this->db->get($table);
  }

  function get_order_limit(string $table, string $order, $limit, $offset = null)
  {
    $this->db->order_by($order);
    if ($offset != null)
      $this->db->limit($limit, $offset);
    else $this->db->limit($limit);
    return $this->db->get($table);
  }

  function get_where_limit(string $table, array $where, $limit, $offset = null)
  {
    $this->db->where($where);
    if ($offset != null)
      $this->db->limit($limit, $offset);
    else $this->db->limit($limit);
    return $this->db->get($table);
  }

  function get_count($table)
  {
    $this->db->from($table);
    return $this->db->count_all_results();
  }

  function get_count_where($table, array $where)
  {
    $this->db->from($table);
    $this->db->where($where);
    return $this->db->count_all_results();
  }

  function get_join_where(string $select, string $table, array $join, array $where)
  {
    $this->db->select($select);
    foreach ($join as $key => $value) {
      $this->db->join($value[0], $value[1], isset($value[2]) ? $value[2] : "left");
    }
    $this->db->where($where);
    return $this->db->get($table);
  }

  function select_join_where(string $select, string $table, array $join, array $where)
  {
    $this->db->select($select);
    $this->db->from($table);
    foreach ($join as $key => $value) {
      $this->db->join($value[0], $value[1], isset($value[2]) ? $value[2] : "left");
    }

    foreach ($where as $key => $value) {
      $this->db->where($value);
    }
  }

  function get_select_join_where(string $select, string $table, array $join, array $where)
  {
    $this->select_join_where($select, $table, $join, $where);
    return $this->db->get();
  }

  function select_join_where_order(string $select, string $table, array $join, array $where, string $order)
  {
    $this->select_join_where($select, $table, $join, $where);
    $this->db->order_by($order);
  }

  function get_select_join_where_order(string $select, string $table, array $join, array $where, string $order)
  {
    $this->select_join_where($select, $table, $join, $where);
    $this->db->order_by($order);

    return $this->db->get();
  }
}
